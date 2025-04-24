use std::{convert::Infallible, io::Cursor, sync::Arc, time::Duration};

use anyhow::{Ok, Result, bail};
use rand::{Rng, distributions::Standard, thread_rng};
use rustc_hash::FxHashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, copy},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    select, spawn,
    sync::{
        RwLock,
        broadcast::{self},
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
    time::timeout,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{info, warn};

use crate::{
    SPECIAL_PACKET_ID,
    msg::Message,
    util::{read_var_int, read_var_int_with_len, split_stream_into_buffered, write_var_int},
};

#[derive(Debug)]
pub enum ServerConnectionEvent {
    CreateNonce {
        nonce: u32,
        incoming_sender: UnboundedSender<Vec<u8>>,
    },
    RemoveNonce(u32),
    SendData {
        nonce: u32,
        data: Vec<u8>,
    },
    ReplaceTrueStream {
        reader: BufReader<OwnedReadHalf>,
        writer: BufWriter<OwnedWriteHalf>,
    },
}

#[inline]
async fn read_from_parent(
    mut reader: BufReader<OwnedReadHalf>,
    nonce_to_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Vec<u8>>>>>,
) -> Result<Infallible> {
    loop {
        let message = Message::read(&mut reader).await?;

        match message {
            Message::RemoveNonce(nonce) => {
                nonce_to_sender.write().await.remove(&nonce);
            }
            Message::Message { nonce, data } => {
                let map = nonce_to_sender.read().await;
                let Some(sender) = map.get(&nonce) else {
                    continue;
                };

                if sender.send(data).is_err() {
                    drop(map);
                    nonce_to_sender.write().await.remove(&nonce);
                }
            }
            _ => continue,
        };
    }
}

#[inline]
pub async fn start_proxying_parent(
    mut event_receiver: UnboundedReceiver<ServerConnectionEvent>,
) -> Result<()> {
    let mut true_stream: Option<(
        AbortOnDropHandle<Result<Infallible>>,
        BufWriter<OwnedWriteHalf>,
    )> = None;
    let nonce_to_sender = Arc::new(RwLock::new(FxHashMap::default()));

    while let Some(event) = event_receiver.recv().await {
        let (mut writer, message) = match (true_stream.as_mut(), event) {
            (
                Some((_, writer)),
                ServerConnectionEvent::CreateNonce {
                    nonce,
                    incoming_sender,
                },
            ) => {
                nonce_to_sender.write().await.insert(nonce, incoming_sender);

                (writer, Message::AddNonce(nonce))
            }
            (Some((_, writer)), ServerConnectionEvent::RemoveNonce(nonce)) => {
                (writer, Message::RemoveNonce(nonce))
            }
            (Some((_, writer)), ServerConnectionEvent::SendData { nonce, data }) => {
                (writer, Message::Message { nonce, data })
            }
            (Some(_) | None, ServerConnectionEvent::ReplaceTrueStream { reader, writer }) => {
                info!("new true stream");

                nonce_to_sender.write().await.clear();
                true_stream = Some((
                    AbortOnDropHandle::new(spawn(read_from_parent(
                        reader,
                        nonce_to_sender.clone(),
                    ))),
                    writer,
                ));
                continue;
            }
            what => {
                warn!("received event before we were ready to receive it {what:?}");
                continue;
            }
        };

        message.write(&mut writer).await?;
        writer.flush().await?;
    }

    Ok(())
}

#[inline]
async fn read<R: AsyncRead + Unpin>(
    mut reader: R,
    event_sender: UnboundedSender<ServerConnectionEvent>,
    nonce: u32,
) -> Result<Infallible> {
    let mut buffer = Cursor::new(Vec::new());

    loop {
        buffer.set_position(0);

        let length = read_var_int(&mut reader).await?;
        if length > 2097151 {
            bail!("Client sent oversized packet");
        }

        copy(&mut (&mut reader).take(length.try_into()?), &mut buffer).await?;
        event_sender.send(ServerConnectionEvent::SendData {
            nonce,
            data: buffer.get_ref()[..buffer.position() as usize].to_vec(),
        })?;
    }
}

#[inline]
async fn start_proxying_child<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    event_sender: UnboundedSender<ServerConnectionEvent>,
    packet_length: usize,
    packet_id: i32,
) -> Result<()> {
    if packet_length > 65535 {
        bail!("Client sent oversized initial packet");
    }

    let (incoming_sender, mut incoming_receiver) = unbounded_channel();
    let nonce: u32 = thread_rng().sample(Standard);

    event_sender.send(ServerConnectionEvent::CreateNonce {
        nonce,
        incoming_sender,
    })?;

    let mut initial_packet_buffer = Vec::new();

    write_var_int(&mut initial_packet_buffer, packet_id).await?;

    timeout(
        Duration::from_secs(15),
        copy(
            &mut (&mut reader).take(packet_length as u64),
            &mut initial_packet_buffer,
        ),
    )
    .await??;

    event_sender.send(ServerConnectionEvent::SendData {
        nonce,
        data: initial_packet_buffer,
    })?;

    let (death_sender, mut death_receiver) = broadcast::channel(1);
    let death_sender_clone = death_sender.clone();
    let mut death_receiver_clone = death_receiver.resubscribe();
    let event_sender_clone = event_sender.clone();

    spawn(async move {
        select! {
            res = read(reader, event_sender_clone, nonce) => {
                warn!("minecraft read died because {res:?}")
            },
            _ = death_receiver_clone.recv() => {
                warn!("death received")
            }
        }

        let _ = death_sender_clone.send(());
    });

    let res: Result<Infallible> = async {
        loop {
            let body = select! {
                body = incoming_receiver.recv() => {
                    body
                },
                _ = death_receiver.recv() => {
                    None
                }
            };

            let Some(body) = body else {
                bail!("incoming packet sender dropped/death sent")
            };

            write_var_int(&mut writer, body.len().try_into()?).await?;
            writer.write_all(&body).await?;
            writer.flush().await?;
        }
    }
    .await;

    info!("minecraft write died because {res:?}");

    let _ = death_sender.send(());
    event_sender.send(ServerConnectionEvent::RemoveNonce(nonce))?;

    Ok(())
}

#[inline]
pub async fn handle_initial_connection(
    stream: TcpStream,
    event_sender: UnboundedSender<ServerConnectionEvent>,
) -> Result<()> {
    stream.set_nodelay(true)?;

    let (mut reader, writer) = split_stream_into_buffered(stream);

    let (packet_length, (packet_id, packet_id_len)) = timeout(Duration::from_secs(30), async {
        let length = read_var_int(&mut reader).await?;
        Ok((length, read_var_int_with_len(&mut reader).await?))
    })
    .await??;

    if packet_id != SPECIAL_PACKET_ID {
        start_proxying_child(
            reader,
            writer,
            event_sender,
            usize::try_from(packet_length)?.saturating_sub(packet_id_len),
            packet_id,
        )
        .await?;
    } else {
        event_sender.send(ServerConnectionEvent::ReplaceTrueStream { reader, writer })?;
    }

    Ok(())
}
