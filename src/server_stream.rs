use std::{convert::Infallible, io::Cursor, sync::Arc, time::Duration};

use anyhow::{Ok, Result, bail};
use chacha20poly1305::XChaCha20Poly1305;
use rand::{Rng, distributions::Standard, rngs::OsRng, thread_rng};
use rustc_hash::FxHashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, copy},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    select, spawn,
    sync::{
        Mutex, RwLock,
        broadcast::{self},
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
    time::timeout,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    SPECIAL_PACKET_ID,
    key::{CRYPT_NONCE_LEN, VerifierAndEncipherer},
    msg::Message,
    stream::{
        read_enciphered_message, read_public_key_and_nonce, write_packet,
        write_public_key_and_nonce,
    },
    util::{
        read_signature, read_var_int, read_var_int_with_len, split_stream_into_buffered,
        write_var_int,
    },
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
    cipher: Option<XChaCha20Poly1305>,
) -> Result<Infallible> {
    let mut ciphertext_buffer = Cursor::new(Vec::new());

    loop {
        match read_enciphered_message(&mut reader, &mut ciphertext_buffer, &cipher).await? {
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

pub struct TrueStream {
    pub _reader_task_drop_guard: AbortOnDropHandle<Result<Infallible>>,
    pub writer: BufWriter<OwnedWriteHalf>,
    pub cipher: Option<XChaCha20Poly1305>,
}

#[inline]
async fn handle_true_stream_request(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: BufWriter<OwnedWriteHalf>,
    nonce_to_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Vec<u8>>>>>,
    verifier: Arc<VerifierAndEncipherer>,
    true_stream: Arc<Mutex<Option<TrueStream>>>,
    do_encryption: bool,
) -> Result<()> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let server_public_key = PublicKey::from(&ephemeral_secret);

    let (client_public_key, client_timestamp) = read_public_key_and_nonce(&mut reader).await?;
    let server_timestamp = write_public_key_and_nonce(&mut writer, &server_public_key).await?;
    let server_signature = verifier.sign_and_verify(
        client_timestamp,
        server_timestamp,
        &client_public_key,
        &server_public_key,
    )?;
    writer.write_all(&server_signature.to_bytes()).await?;
    writer.flush().await?;

    let client_signature = read_signature(&mut reader).await?;

    let cipher = verifier.peer_verify(
        &client_signature,
        ephemeral_secret,
        client_timestamp,
        server_timestamp,
        &client_public_key,
        &server_public_key,
        do_encryption,
    )?;

    info!("auth success, we have a new true stream!");
    nonce_to_sender.write().await.clear();
    *true_stream.lock().await = Some(TrueStream {
        _reader_task_drop_guard: AbortOnDropHandle::new(spawn(read_from_parent(
            reader,
            nonce_to_sender.clone(),
            cipher.clone(),
        ))),
        writer,
        cipher,
    });

    Ok(())
}

#[inline]
pub async fn start_proxying_parent(
    mut event_receiver: UnboundedReceiver<ServerConnectionEvent>,
    verifier: VerifierAndEncipherer,
    do_encryption: bool,
    max_processing_consolidation: usize,
) -> Result<()> {
    let true_stream: Arc<Mutex<Option<TrueStream>>> = Arc::new(Mutex::new(None));
    let nonce_to_sender = Arc::new(RwLock::new(FxHashMap::default()));
    let verifier = Arc::new(verifier);
    let mut nonce_buffer = [0u8; CRYPT_NONCE_LEN];
    let mut plaintext_buffer = Cursor::new(Vec::new());
    let mut message_buffer = Vec::new();

    loop {
        message_buffer.clear();

        let received_messages = event_receiver
            .recv_many(&mut message_buffer, max_processing_consolidation)
            .await;

        if received_messages == 0 {
            return Ok(());
        }

        let mut true_stream_lock = true_stream.lock().await;

        for event in message_buffer.drain(..received_messages) {
            let (true_stream, message) = match (true_stream_lock.as_mut(), event) {
                (
                    Some(true_stream),
                    ServerConnectionEvent::CreateNonce {
                        nonce,
                        incoming_sender,
                    },
                ) => {
                    nonce_to_sender.write().await.insert(nonce, incoming_sender);

                    (true_stream, Message::AddNonce(nonce))
                }
                (Some(true_stream), ServerConnectionEvent::RemoveNonce(nonce)) => {
                    (true_stream, Message::RemoveNonce(nonce))
                }
                (Some(true_stream), ServerConnectionEvent::SendData { nonce, data }) => {
                    (true_stream, Message::Message { nonce, data })
                }
                (Some(_) | None, ServerConnectionEvent::ReplaceTrueStream { reader, writer }) => {
                    info!("new true stream request");

                    let (nonce_to_sender, verifier, true_stream) = (
                        nonce_to_sender.clone(),
                        verifier.clone(),
                        true_stream.clone(),
                    );
                    spawn(async move {
                        match timeout(
                            Duration::from_secs(15),
                            handle_true_stream_request(
                                reader,
                                writer,
                                nonce_to_sender,
                                verifier,
                                true_stream,
                                do_encryption,
                            ),
                        )
                        .await
                        .map_err(anyhow::Error::new)
                        .flatten()
                        {
                            Result::Ok(_) => {}
                            Err(e) => warn!(?e, "auth failure"),
                        }
                    });
                    continue;
                }
                (_, event) => {
                    warn!("received event with invalid order/side: {event:?}");
                    continue;
                }
            };

            match write_packet(
                &mut true_stream.writer,
                &true_stream.cipher,
                &mut plaintext_buffer,
                &mut nonce_buffer,
                &message,
            )
            .await
            {
                Result::Ok(_) => continue,
                Err(e) => {
                    error!(?e, "failed to write to client, state will be reset");
                    true_stream_lock.take();
                    nonce_to_sender.write().await.clear();
                }
            }
        }

        let Some(true_stream) = true_stream_lock.as_mut() else {
            continue;
        };

        match true_stream.writer.flush().await {
            Result::Ok(_) => continue,
            Err(e) => {
                error!(?e, "failed to flush client, state will be reset");
                true_stream_lock.take();
                nonce_to_sender.write().await.clear();
            }
        };
    }
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
    max_processing_consolidation: usize,
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
        let mut packet_buffer = Vec::new();

        loop {
            packet_buffer.clear();

            let received_packets = select! {
                received_packets = incoming_receiver.recv_many(&mut packet_buffer, max_processing_consolidation) => {
                    received_packets
                },
                _ = death_receiver.recv() => {
                    0
                }
            };

            if received_packets == 0 {
                bail!("incoming packet sender dropped/death sent");
            }

            for body in &packet_buffer[..received_packets] {
                write_var_int(&mut writer, body.len().try_into()?).await?;
                writer.write_all(&body).await?;
            }

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
    max_processing_consolidation: usize,
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
            max_processing_consolidation,
        )
        .await?;
    } else {
        event_sender.send(ServerConnectionEvent::ReplaceTrueStream { reader, writer })?;
    }

    Ok(())
}
