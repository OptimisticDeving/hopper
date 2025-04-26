#![feature(result_flattening)]

mod client_stream;
mod key;
mod msg;
mod server_stream;
mod stream;
mod util;
use std::{borrow::Cow, io::Cursor, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::Aead;
use client_stream::{create_fork, send_fork_stream_init_packet, send_true_stream_init_packet};
use key::{CRYPT_NONCE_LEN, VerifierAndEncipherer};
use rand::rngs::OsRng;
use rustc_hash::FxHashMap;
use serde::Deserialize;
use server_stream::{handle_initial_connection, start_proxying_parent};
use stream::{combine_crypt, read_public_key_and_nonce};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    main,
    net::{TcpListener, TcpStream},
    select,
    signal::{
        ctrl_c,
        unix::{SignalKind, signal},
    },
    spawn,
    sync::{Mutex, RwLock, mpsc::unbounded_channel},
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, info, warn};
use tracing_subscriber::fmt;
use util::{read_signature, split_stream_into_buffered};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub const TRUE_STREAM_PACKET_ID: i32 = 0xDEADBEEFu32.cast_signed();
pub const FORK_STREAM_PACKET_ID: i32 = 0xCAFEBABEu32.cast_signed();

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
    pub max_processing_consolidation: usize,
    pub fork_count: usize,
    pub fork_establish_interval: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_server_address: Cow::Borrowed("[::]:25565"),
            proxy_server_address: None,
            client_private_key_path: Cow::Borrowed("./client.key"),
            client_public_key_path: Cow::Borrowed("./client.pub"),
            server_private_key_path: Cow::Borrowed("./server.key"),
            server_public_key_path: Cow::Borrowed("./server.pub"),
            do_encryption: true,
            max_processing_consolidation: usize::MAX,
            fork_count: 15,
            fork_establish_interval: 10,
        }
    }
}

enum ServerWakeEvent {
    Connection((TcpStream, SocketAddr)),
    Terminate,
}

#[main]
async fn main() -> Result<()> {
    fmt().init();

    let config = serde_env::from_env::<Config>()?;

    if !config.do_encryption {
        warn!("encryption disabled in config, this is not supported!")
    }

    let mut rng = OsRng;
    let mut sigint = signal(SignalKind::terminate())?;

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

            let mut establish_interval =
                interval(Duration::from_millis(config.fork_establish_interval));
            establish_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            info!("connecting to {proxy_server_address}");
            let stream = TcpStream::connect(&proxy_server_address).await?;
            establish_interval.tick().await;
            stream.set_nodelay(true)?;
            let (mut reader, mut writer) = split_stream_into_buffered(stream);

            let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
            let client_public_key = PublicKey::from(&ephemeral_secret);
            let client_nonce =
                send_true_stream_init_packet(&mut writer, &client_public_key).await?;

            let (server_public_key, server_nonce) = read_public_key_and_nonce(&mut reader).await?;

            let client_signature = verifier.true_stream_sign(
                client_nonce,
                server_nonce,
                &client_public_key,
                &server_public_key,
            );

            writer.write_all(&client_signature.to_bytes()).await?;
            writer.flush().await?;

            let server_signature = read_signature(&mut reader).await?;

            let cipher = verifier.true_stream_peer_verify(
                &server_signature,
                ephemeral_secret,
                client_nonce,
                server_nonce,
                &client_public_key,
                &server_public_key,
                config.do_encryption,
            )?;

            let combination = combine_crypt(
                client_nonce,
                server_nonce,
                &client_public_key,
                &server_public_key,
            );

            let forks = Arc::new(Mutex::new(Default::default()));
            let nonce_to_conn_map = Arc::new(RwLock::new(FxHashMap::default()));
            let mut fork_join_set = JoinSet::new();

            let tcp_server_address: Arc<str> = Arc::from(config.tcp_server_address);

            let mut fork_nonces = Vec::with_capacity(config.fork_count);

            let nonce_byte_count = 8 * config.fork_count;
            let mut nonce_bytes = if let Some(cipher) = &cipher {
                let mut nonce = [0u8; CRYPT_NONCE_LEN];
                reader.read_exact(&mut nonce).await?;
                let ciphertext_size = 16 + nonce_byte_count;
                let mut ciphertext = vec![0u8; ciphertext_size];
                reader.read_exact(&mut ciphertext).await?;
                let plaintext = cipher
                    .decrypt(&nonce.into(), ciphertext.as_ref())
                    .map_err(|e| anyhow!("{e}"))?;
                Cursor::new(plaintext)
            } else {
                let mut nonce_bytes = vec![0u8; nonce_byte_count];
                reader.read_exact(&mut nonce_bytes).await?;
                Cursor::new(nonce_bytes)
            };

            for _ in 0..config.fork_count {
                fork_nonces.push(nonce_bytes.read_u64().await?);
            }

            let (main_message_sender, main_fork_read, main_fork_write) = create_fork(
                reader,
                writer,
                config.max_processing_consolidation,
                &cipher,
                tcp_server_address.clone(),
                nonce_to_conn_map.clone(),
                forks.clone(),
            );

            fork_join_set.spawn(main_fork_read);
            fork_join_set.spawn(main_fork_write);
            forks.lock().await.push_front(main_message_sender);

            for (idx, fork_nonce) in fork_nonces.into_iter().enumerate() {
                info!("waiting...");
                establish_interval.tick().await;
                info!("creating fork #{idx}");

                let fork_stream = TcpStream::connect(&proxy_server_address).await?;
                fork_stream.set_nodelay(true)?;

                let (fork_reader, mut fork_writer) = split_stream_into_buffered(fork_stream);
                send_fork_stream_init_packet(
                    &mut fork_writer,
                    fork_nonce,
                    &verifier,
                    &combination,
                    &cipher,
                )
                .await?;

                let (message_sender, read, write) = create_fork(
                    fork_reader,
                    fork_writer,
                    config.max_processing_consolidation,
                    &cipher,
                    tcp_server_address.clone(),
                    nonce_to_conn_map.clone(),
                    forks.clone(),
                );

                fork_join_set.spawn(read);
                fork_join_set.spawn(write);
                forks.lock().await.push_front(message_sender);
            }

            let why = select! {
                ret = fork_join_set.join_next() => {
                    ret
                }
                _ = sigint.recv() => {
                    info!("received sigint");
                    return Ok(());
                }
                _ = ctrl_c() => {
                    info!("received ctrl+c");
                    return Ok(());
                }
            };

            error!("error in fork: {why:?}");
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
                config.max_processing_consolidation,
                config.fork_count,
            ));

            loop {
                let event = select! {
                    conn = listener.accept() => {
                        ServerWakeEvent::Connection(conn?)
                    }
                    _ = sigint.recv() => {
                        ServerWakeEvent::Terminate
                    },
                    _ = ctrl_c() => {
                        ServerWakeEvent::Terminate
                    }
                };

                match event {
                    ServerWakeEvent::Connection((stream, _)) => {
                        spawn(handle_initial_connection(
                            stream,
                            event_sender.clone(),
                            config.max_processing_consolidation,
                        ));
                    }
                    ServerWakeEvent::Terminate => {
                        info!("received termination signal");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
