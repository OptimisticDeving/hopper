mod client_stream;
mod msg;
mod server_stream;
mod util;

use std::sync::Arc;

use anyhow::Result;
use client_stream::{
    handle_mc_proxy_read, handle_write, send_special_packet, start_writing_messages,
};
use msg::Message;
use rustc_hash::FxHashMap;
use serde::Deserialize;
use server_stream::{handle_initial_connection, start_proxying_parent};
use tokio::{
    main,
    net::{TcpListener, TcpStream},
    spawn,
    sync::{RwLock, mpsc::unbounded_channel},
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{info, warn};
use tracing_subscriber::fmt;
use util::split_stream_into_buffered;

pub const SPECIAL_PACKET_ID: i32 = 0xDEADBEEFu32.cast_signed();

#[derive(Debug, Deserialize)]
struct Config {
    pub tcp_server_address: String,
    pub proxy_server_address: Option<String>,
}

#[main]
async fn main() -> Result<()> {
    fmt().init();

    let config = serde_env::from_env::<Config>()?;

    match config.proxy_server_address {
        Some(proxy_server_address) => {
            info!("connecting to {proxy_server_address}");
            let stream = TcpStream::connect(&proxy_server_address).await?;
            stream.set_nodelay(true)?;
            let (mut reader, mut writer) = split_stream_into_buffered(stream);
            send_special_packet(&mut writer).await?;

            let (message_sender, message_receiver) = unbounded_channel();
            spawn(start_writing_messages(writer, message_receiver));

            let nonce_to_connection = Arc::new(RwLock::new(FxHashMap::default()));

            loop {
                let message = Message::read(&mut reader).await?;

                match message {
                    Message::AddNonce(nonce) => {
                        let stream = match TcpStream::connect(&config.tcp_server_address).await {
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

            let listener = TcpListener::bind(config.tcp_server_address).await?;
            let (event_sender, event_receiver) = unbounded_channel();

            spawn(start_proxying_parent(event_receiver));

            loop {
                spawn(handle_initial_connection(
                    listener.accept().await?.0,
                    event_sender.clone(),
                ));
            }
        }
    }
}
