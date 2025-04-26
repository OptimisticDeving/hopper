use std::{collections::VecDeque, convert::Infallible, io::Cursor, sync::Arc, time::Duration};

use anyhow::{Ok, Result, anyhow, bail};
use chacha20poly1305::{XChaCha20Poly1305, aead::Aead};
use ed25519_dalek::SIGNATURE_LENGTH;
use rand::{Rng, distributions::Standard, rngs::OsRng, thread_rng};
use rustc_hash::{FxBuildHasher, FxHashMap, FxHashSet};
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
    FORK_STREAM_PACKET_ID, TRUE_STREAM_PACKET_ID,
    key::{CRYPT_NONCE_LEN, VerifierAndEncipherer},
    msg::Message,
    stream::{
        CryptCombination, anon_write, combine_crypt, read_enciphered_message,
        read_public_key_and_nonce, select_first_from_deque_appending_to_back_mapped, write_packet,
        write_public_key_and_nonce,
    },
    util::{
        read_exact, read_signature, read_var_int, read_var_int_with_len,
        split_stream_into_buffered, write_var_int,
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
    AttemptTrueStreamReplacement {
        reader: BufReader<OwnedReadHalf>,
        writer: BufWriter<OwnedWriteHalf>,
    },
    AttemptForkStream {
        reader: BufReader<OwnedReadHalf>,
        writer: BufWriter<OwnedWriteHalf>,
    },
}

#[inline]
async fn read_from_parent(
    mut reader: BufReader<OwnedReadHalf>,
    nonce_to_mc_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Vec<u8>>>>>,
    nonce_to_true_stream_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Message>>>>,
    cipher: Option<XChaCha20Poly1305>,
) -> Result<Infallible> {
    let mut ciphertext_buffer = Cursor::new(Vec::new());

    loop {
        match read_enciphered_message(&mut reader, &mut ciphertext_buffer, &cipher).await? {
            Message::RemoveNonce(nonce) => {
                info!("removing nonce {nonce}");
                nonce_to_mc_sender.write().await.remove(&nonce);
                nonce_to_true_stream_sender.write().await.remove(&nonce);
            }
            Message::Message { nonce, data } => {
                let map = nonce_to_mc_sender.read().await;
                let Some(sender) = map.get(&nonce) else {
                    continue;
                };

                if sender.send(data).is_err() {
                    drop(map);
                    nonce_to_mc_sender.write().await.remove(&nonce);
                }
            }
            _ => continue,
        };
    }
}

#[inline]
async fn write_to_parent(
    mut writer: BufWriter<OwnedWriteHalf>,
    mut message_receiver: UnboundedReceiver<Message>,
    cipher: Option<XChaCha20Poly1305>,
    max_processing_consolidation: usize,
) -> Result<()> {
    let mut packet_buffer = Vec::new();
    let mut plaintext_buffer = Cursor::new(Vec::new());
    let mut nonce_buffer = [0u8; CRYPT_NONCE_LEN];

    loop {
        packet_buffer.clear();

        let received_messages = message_receiver
            .recv_many(&mut packet_buffer, max_processing_consolidation)
            .await;

        if received_messages == 0 {
            return Ok(());
        }

        for message in &packet_buffer[..received_messages] {
            write_packet(
                &mut writer,
                &cipher,
                &mut plaintext_buffer,
                &mut nonce_buffer,
                message,
            )
            .await?;
        }

        writer.flush().await?;
    }
}

pub struct TrueStreamFork {
    pub _reader_task_drop_guard: AbortOnDropHandle<Result<Infallible>>,
    pub _writer_task_drop_guard: AbortOnDropHandle<Result<()>>,
    pub message_sender: UnboundedSender<Message>,
    pub nonce: u64,
}

pub struct TrueStream {
    pub cipher: Option<XChaCha20Poly1305>,
    pub remaining_fork_nonces: FxHashSet<u64>,
    pub combination: CryptCombination,
    pub forks: VecDeque<TrueStreamFork>,
}

#[inline]
async fn handle_true_stream_request(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: BufWriter<OwnedWriteHalf>,
    nonce_to_mc_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Vec<u8>>>>>,
    nonce_to_true_stream_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Message>>>>,
    verifier: Arc<VerifierAndEncipherer>,
    true_stream: Arc<Mutex<Option<TrueStream>>>,
    do_encryption: bool,
    max_processing_consolidation: usize,
    fork_count: usize,
) -> Result<()> {
    let mut rng = OsRng;
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let server_public_key = PublicKey::from(&ephemeral_secret);

    let (client_public_key, client_nonce) = read_public_key_and_nonce(&mut reader).await?;
    let server_nonce = write_public_key_and_nonce(&mut writer, &server_public_key).await?;
    let server_signature = verifier.true_stream_sign(
        client_nonce,
        server_nonce,
        &client_public_key,
        &server_public_key,
    );
    writer.write_all(&server_signature.to_bytes()).await?;
    writer.flush().await?;

    let client_signature = read_signature(&mut reader).await?;

    let cipher = verifier.true_stream_peer_verify(
        &client_signature,
        ephemeral_secret,
        client_nonce,
        server_nonce,
        &client_public_key,
        &server_public_key,
        do_encryption,
    )?;

    let mut remaining_fork_nonces = FxHashSet::with_capacity_and_hasher(fork_count, FxBuildHasher);
    let mut fork_nonce_body = Cursor::new(Vec::new());

    for _ in 0..fork_count {
        let fork_nonce: u64 = rng.r#gen();
        remaining_fork_nonces.insert(fork_nonce);
        fork_nonce_body.write_u64(fork_nonce).await?;
    }

    anon_write(
        &mut writer,
        &cipher,
        &fork_nonce_body.get_ref()[..fork_nonce_body.position() as usize],
    )
    .await?;

    info!("auth success, we have a new true stream!");
    nonce_to_mc_sender.write().await.clear();
    nonce_to_true_stream_sender.write().await.clear();

    let (message_sender, message_receiver) = unbounded_channel();

    *true_stream.lock().await = Some(TrueStream {
        cipher: cipher.clone(),
        remaining_fork_nonces,
        combination: combine_crypt(
            client_nonce,
            server_nonce,
            &client_public_key,
            &server_public_key,
        ),
        forks: VecDeque::from([TrueStreamFork {
            _reader_task_drop_guard: AbortOnDropHandle::new(spawn(read_from_parent(
                reader,
                nonce_to_mc_sender,
                nonce_to_true_stream_sender,
                cipher.clone(),
            ))),
            _writer_task_drop_guard: AbortOnDropHandle::new(spawn(write_to_parent(
                writer,
                message_receiver,
                cipher,
                max_processing_consolidation,
            ))),
            message_sender,
            nonce: 0,
        }]),
    });

    Ok(())
}

#[inline]
async fn handle_fork_stream_request(
    mut reader: BufReader<OwnedReadHalf>,
    writer: BufWriter<OwnedWriteHalf>,
    nonce_to_mc_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Vec<u8>>>>>,
    nonce_to_true_stream_sender: Arc<RwLock<FxHashMap<u32, UnboundedSender<Message>>>>,
    verifier: Arc<VerifierAndEncipherer>,
    true_stream: Arc<Mutex<Option<TrueStream>>>,
    original_combined_nonce: u64,
    original_cipher: Option<XChaCha20Poly1305>,
    max_processing_consolidation: usize,
) -> Result<()> {
    let (fork_nonce, stream_nonce, signature) = if let Some(cipher) = original_cipher {
        let cipher_nonce = read_exact(&mut reader).await?;
        let mut ciphertext = [0u8; (8 * 2) + SIGNATURE_LENGTH + 16];
        reader.read_exact(&mut ciphertext).await?;

        let mut reader = Cursor::new(
            cipher
                .decrypt(&cipher_nonce.into(), ciphertext.as_slice())
                .map_err(|e| anyhow!("{e}"))?,
        );

        (
            reader.read_u64().await?,
            reader.read_u64().await?,
            read_signature(&mut reader).await?,
        )
    } else {
        (
            reader.read_u64().await?,
            reader.read_u64().await?,
            read_signature(&mut reader).await?,
        )
    };

    let mut true_stream_lock = true_stream.lock().await;
    let true_stream = true_stream_lock.as_mut().unwrap();

    if true_stream.combination.combined_nonces != original_combined_nonce {
        bail!("mismatched combined nonces");
    }

    // don't remove it here so that real fork nonce attempts can't be interfered with
    if !true_stream.remaining_fork_nonces.contains(&fork_nonce) {
        bail!("unknown fork nonce");
    }

    verifier.fork_stream_verify(
        &signature,
        &true_stream.combination,
        fork_nonce,
        stream_nonce,
    )?;

    true_stream.remaining_fork_nonces.remove(&fork_nonce);

    let (message_sender, message_receiver) = unbounded_channel();
    true_stream.forks.push_front(TrueStreamFork {
        _reader_task_drop_guard: AbortOnDropHandle::new(spawn(read_from_parent(
            reader,
            nonce_to_mc_sender.clone(),
            nonce_to_true_stream_sender.clone(),
            true_stream.cipher.clone(),
        ))),
        _writer_task_drop_guard: AbortOnDropHandle::new(spawn(write_to_parent(
            writer,
            message_receiver,
            true_stream.cipher.clone(),
            max_processing_consolidation,
        ))),
        message_sender,
        nonce: fork_nonce,
    });

    Ok(())
}

#[inline]
fn handle_authentication_task<F: Future<Output = Result<()>> + Send + 'static>(task: F) {
    spawn(async move {
        match timeout(Duration::from_secs(15), task)
            .await
            .map_err(anyhow::Error::new)
            .flatten()
        {
            Result::Ok(_) => {}
            Err(e) => warn!(?e, "auth task failure"),
        }
    });
}

#[inline]
pub async fn start_proxying_parent(
    mut event_receiver: UnboundedReceiver<ServerConnectionEvent>,
    verifier: VerifierAndEncipherer,
    do_encryption: bool,
    max_processing_consolidation: usize,
    fork_count: usize,
) -> Result<()> {
    let true_stream: Arc<Mutex<Option<TrueStream>>> = Arc::new(Mutex::new(None));
    let nonce_to_mc_sender = Arc::new(RwLock::new(FxHashMap::default()));
    let nonce_to_true_stream_sender = Arc::new(RwLock::new(FxHashMap::default()));
    let verifier = Arc::new(verifier);
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
            let (nonce, message) = match (true_stream_lock.as_mut(), event) {
                (
                    Some(true_stream),
                    ServerConnectionEvent::CreateNonce {
                        nonce,
                        incoming_sender,
                    },
                ) => {
                    if !true_stream.remaining_fork_nonces.is_empty() {
                        warn!("connection attempted with remaining fork nonces");
                        continue;
                    }

                    nonce_to_mc_sender
                        .write()
                        .await
                        .insert(nonce, incoming_sender);

                    let selected_sender = select_first_from_deque_appending_to_back_mapped(
                        |fork| {
                            info!("selecting fork #{}", fork.nonce);
                            &fork.message_sender
                        },
                        &mut true_stream.forks,
                    );

                    nonce_to_true_stream_sender
                        .write()
                        .await
                        .insert(nonce, selected_sender);

                    (nonce, Message::AddNonce(nonce))
                }
                (Some(_), ServerConnectionEvent::RemoveNonce(nonce)) => {
                    (nonce, Message::RemoveNonce(nonce))
                }
                (Some(_), ServerConnectionEvent::SendData { nonce, data }) => {
                    (nonce, Message::Message { nonce, data })
                }
                (_, ServerConnectionEvent::AttemptTrueStreamReplacement { reader, writer }) => {
                    info!("new true stream request");

                    handle_authentication_task(handle_true_stream_request(
                        reader,
                        writer,
                        nonce_to_mc_sender.clone(),
                        nonce_to_true_stream_sender.clone(),
                        verifier.clone(),
                        true_stream.clone(),
                        do_encryption,
                        max_processing_consolidation,
                        fork_count,
                    ));

                    continue;
                }
                (
                    Some(true_stream_ref),
                    ServerConnectionEvent::AttemptForkStream { reader, writer },
                ) => {
                    info!("new fork stream request");

                    handle_authentication_task(handle_fork_stream_request(
                        reader,
                        writer,
                        nonce_to_mc_sender.clone(),
                        nonce_to_true_stream_sender.clone(),
                        verifier.clone(),
                        true_stream.clone(),
                        true_stream_ref.combination.combined_nonces,
                        true_stream_ref.cipher.clone(),
                        max_processing_consolidation,
                    ));

                    continue;
                }
                (_, event) => {
                    warn!("received event with invalid order/side: {event:?}");
                    continue;
                }
            };

            let nonce_to_true_stream_writer = nonce_to_true_stream_sender.read().await;
            let Some(nonce_to_associated_writer) = nonce_to_true_stream_writer.get(&nonce) else {
                warn!("no associated writer for {nonce}");
                continue;
            };

            match nonce_to_associated_writer.send(message) {
                Result::Ok(_) => continue,
                Err(e) => {
                    error!(?e, "failed to write to client, state will be reset");
                    true_stream_lock.take();
                    nonce_to_mc_sender.write().await.clear();
                }
            }
        }
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

    match packet_id {
        TRUE_STREAM_PACKET_ID => event_sender
            .send(ServerConnectionEvent::AttemptTrueStreamReplacement { reader, writer })?,
        FORK_STREAM_PACKET_ID => {
            event_sender.send(ServerConnectionEvent::AttemptForkStream { reader, writer })?
        }
        _ => {
            start_proxying_child(
                reader,
                writer,
                event_sender,
                usize::try_from(packet_length)?.saturating_sub(packet_id_len),
                packet_id,
                max_processing_consolidation,
            )
            .await?
        }
    }

    Ok(())
}
