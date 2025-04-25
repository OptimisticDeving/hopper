#![feature(result_flattening)]

mod client_stream;
mod key;
mod msg;
mod server_stream;
mod stream;
mod util;
use std::{borrow::Cow, io::Cursor, path::Path, sync::Arc};

use anyhow::Result;
use client_stream::{
    handle_mc_proxy_read, handle_write, send_special_packet, start_writing_messages,
};
use key::VerifierAndEncipherer;
use msg::Message;
use rand::rngs::OsRng;
use rustc_hash::FxHashMap;
use serde::Deserialize;
use server_stream::{handle_initial_connection, start_proxying_parent};
use stream::{read_enciphered_message, read_public_key_and_nonce};
use tokio::{
    io::AsyncWriteExt,
    main,
    net::{TcpListener, TcpStream},
    spawn,
    sync::{RwLock, mpsc::unbounded_channel},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{info, warn};
use tracing_subscriber::fmt;
use util::{read_signature, split_stream_into_buffered};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub const SPECIAL_PACKET_ID: i32 = 0xDEADBEEFu32.cast_signed();

#[derive(Debug, Deserialize)]
#[serde(default)]
struct Config {
    pub tcp_server_address: Cow<'static, str>,
    pub proxy_server_address: Option<String>,
    pub client_private_key_path: Cow<'static, str>,
    pub client_public_key_path: Cow<'static, str>,
    pub server_private_key_path: Cow<'static, str>,
    pub server_public_key_path: Cow<'static, str>,
    pub do_encryption: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_server_address: Cow::Borrowed("127.0.0.1:25565"),
            proxy_server_address: None,
            client_private_key_path: Cow::Borrowed("./client.key"),
            client_public_key_path: Cow::Borrowed("./client.pub"),
            server_private_key_path: Cow::Borrowed("./server.key"),
            server_public_key_path: Cow::Borrowed("./server.pub"),
            do_encryption: true,
        }
    }
}

#[main]
async fn main() -> Result<()> {
    fmt().init();

    let config = serde_env::from_env::<Config>()?;

    if !config.do_encryption {
        warn!("encryption disabled in config, this is not supported!")
    }

    let mut rng = OsRng;
    match config.proxy_server_address {
        Some(proxy_server_address) => {
            let verifier = VerifierAndEncipherer::generate(
                Path::new(config.client_private_key_path.as_ref()),
                Path::new(config.client_public_key_path.as_ref()),
                Path::new(config.server_public_key_path.as_ref()),
                &mut rng,
                true,
            )
            .await?;

            info!("connecting to {proxy_server_address}");
            let stream = TcpStream::connect(&proxy_server_address).await?;
            stream.set_nodelay(true)?;
            let (mut reader, mut writer) = split_stream_into_buffered(stream);

            let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
            let client_public_key = PublicKey::from(&ephemeral_secret);
            let client_nonce = send_special_packet(&mut writer, &client_public_key).await?;

            let (server_public_key, server_nonce) = read_public_key_and_nonce(&mut reader).await?;

            let client_signature = verifier.sign_and_verify(
                client_nonce,
                server_nonce,
                &client_public_key,
                &server_public_key,
            )?;

            writer.write_all(&client_signature.to_bytes()).await?;
            writer.flush().await?;

            let server_signature = read_signature(&mut reader).await?;

            let cipher = verifier.peer_verify(
                &server_signature,
                ephemeral_secret,
                client_nonce,
                server_nonce,
                &client_public_key,
                &server_public_key,
                config.do_encryption,
            )?;

            let (message_sender, message_receiver) = unbounded_channel();
            spawn(start_writing_messages(
                writer,
                message_receiver,
                cipher.clone(),
            ));

            let nonce_to_connection = Arc::new(RwLock::new(FxHashMap::default()));
            let mut ciphertext_buffer = Cursor::new(Vec::new());
            loop {
                match read_enciphered_message(&mut reader, &mut ciphertext_buffer, &cipher).await? {
                    Message::AddNonce(nonce) => {
                        let stream =
                            match TcpStream::connect(config.tcp_server_address.as_ref()).await {
                                Ok(stream) => stream,
                                Err(e) => {
                                    warn!(?e, "failed to connect to the true server");
                                    message_sender.send(Message::RemoveNonce(nonce))?;
                                    continue;
                                }
                            };

                        stream.set_nodelay(true)?;
                        let (reader, writer) = split_stream_into_buffered(stream);
                        let (write_sender, write_receiver) = unbounded_channel();
                        spawn(handle_write(writer, write_receiver));

                        nonce_to_connection.write().await.insert(
                            nonce,
                            (
                                AbortOnDropHandle::new(spawn(handle_mc_proxy_read(
                                    reader,
                                    nonce,
                                    message_sender.clone(),
                                    nonce_to_connection.clone(),
                                ))),
                                write_sender,
                            ),
                        );
                    }
                    Message::RemoveNonce(nonce) => {
                        nonce_to_connection.write().await.remove(&nonce);
                    }
                    Message::Message { nonce, data } => {
                        let read = nonce_to_connection.read().await;
                        let Some((_, write_sender)) = read.get(&nonce) else {
                            continue;
                        };

                        write_sender.send(data)?;
                    }
                }
            }
        }
        None => {
            info!("binding to {}", config.tcp_server_address);

            let verifier = VerifierAndEncipherer::generate(
                Path::new(config.server_private_key_path.as_ref()),
                Path::new(config.server_public_key_path.as_ref()),
                Path::new(config.client_public_key_path.as_ref()),
                &mut rng,
                false,
            )
            .await?;

            let listener = TcpListener::bind(config.tcp_server_address.as_ref()).await?;
            let (event_sender, event_receiver) = unbounded_channel();

            spawn(start_proxying_parent(
                event_receiver,
                verifier,
                config.do_encryption,
            ));

            loop {
                spawn(handle_initial_connection(
                    listener.accept().await?.0,
                    event_sender.clone(),
                ));
            }
        }
    }
}
