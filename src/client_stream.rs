use std::{collections::VecDeque, convert::Infallible, io::Cursor, sync::Arc};

use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use rand::{Rng, rngs::OsRng};
use rustc_hash::FxHashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy},
    net::TcpStream,
    spawn,
    sync::{
        Mutex, RwLock,
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use crate::{
    FORK_STREAM_PACKET_ID, TRUE_STREAM_PACKET_ID,
    key::{CRYPT_NONCE_LEN, VerifierAndEncipherer},
    msg::Message,
    stream::{
        CryptCombination, anon_write, read_enciphered_message,
        select_first_from_deque_appending_to_back_passthrough, write_packet,
        write_public_key_and_nonce,
    },
    util::{read_var_int, split_stream_into_buffered, write_var_int},
};

#[inline]
pub async fn send_true_stream_init_packet<W: AsyncWrite + Unpin>(
    mut writer: W,
    public_key: &PublicKey,
) -> Result<u64> {
    writer.write_u8(0).await?; // we don't need the length
    write_var_int(&mut writer, TRUE_STREAM_PACKET_ID).await?;
    let nonce = write_public_key_and_nonce(&mut writer, public_key).await?;
    writer.flush().await?;

    Ok(nonce)
}

#[inline]
pub async fn send_fork_stream_init_packet<W: AsyncWrite + Unpin>(
    mut writer: W,
    fork_nonce: u64,
    verifier: &VerifierAndEncipherer,
    combination: &CryptCombination,
    cipher: &Option<XChaCha20Poly1305>,
) -> Result<()> {
    writer.write_u8(0).await?;
    write_var_int(&mut writer, FORK_STREAM_PACKET_ID).await?;

    let mut rng = OsRng;
    let stream_nonce: u64 = rng.r#gen();

    let mut body = Cursor::new(Vec::new());
    body.write_u64(fork_nonce).await?;
    body.write_u64(stream_nonce).await?;
    let signature = verifier.fork_stream_sign(combination, fork_nonce, stream_nonce);
    body.write_all(&signature.to_bytes()).await?;

    anon_write(
        &mut writer,
        cipher,
        &body.get_ref()[..body.position() as usize],
    )
    .await?;

    Ok(())
}

#[inline]
pub async fn handle_fork_write<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: UnboundedReceiver<Message>,
    cipher: Option<XChaCha20Poly1305>,
    max_processing_consolidation: usize,
) -> Result<()> {
    let mut nonce = [0u8; CRYPT_NONCE_LEN];
    let mut plaintext_buffer = Cursor::new(Vec::new());
    let mut message_buffer = Vec::new();

    loop {
        message_buffer.clear();

        let received_messages = receiver
            .recv_many(&mut message_buffer, max_processing_consolidation)
            .await;

        if received_messages == 0 {
            break;
        }

        for message in &message_buffer[..received_messages] {
            write_packet(
                &mut writer,
                &cipher,
                &mut plaintext_buffer,
                &mut nonce,
                message,
            )
            .await?;
        }

        writer.flush().await?;
    }

    Ok(())
}

#[inline]
async fn handle_read<R: AsyncRead + Unpin>(
    mut reader: R,
    message_sender: UnboundedSender<Message>,
    nonce: u32,
) -> Result<Infallible> {
    let mut buffer = Cursor::new(Vec::new());

    loop {
        buffer.set_position(0);

        let length = read_var_int(&mut reader).await?;
        copy(&mut (&mut reader).take(length.try_into()?), &mut buffer).await?;
        message_sender.send(Message::Message {
            nonce,
            data: buffer.get_ref()[..buffer.position() as usize].to_vec(),
        })?;
    }
}

#[inline]
pub async fn handle_mc_proxy_read<R: AsyncRead + Unpin, V>(
    reader: R,
    nonce: u32,
    message_sender: UnboundedSender<Message>,
    nonce_to_conn_map: Arc<RwLock<FxHashMap<u32, V>>>,
) -> Result<()> {
    info!(
        "mc half ended because {:?}",
        handle_read(reader, message_sender, nonce).await
    );

    nonce_to_conn_map.write().await.remove(&nonce);
    Ok(())
}

#[inline]
pub async fn handle_write<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: UnboundedReceiver<Vec<u8>>,
    max_processing_consolidation: usize,
) -> Result<()> {
    let mut packet_buffer = Vec::new();

    loop {
        packet_buffer.clear();

        let received_packets = receiver
            .recv_many(&mut packet_buffer, max_processing_consolidation)
            .await;

        if received_packets == 0 {
            return Ok(());
        }

        for body in &packet_buffer[..received_packets] {
            write_var_int(&mut writer, body.len().try_into()?).await?;
            writer.write_all(body).await?;
        }

        writer.flush().await?;
    }
}

pub struct ClientStream {
    _read_drop_guard: AbortOnDropHandle<Result<()>>,
    write_sender: UnboundedSender<Vec<u8>>,
}

#[inline]
pub async fn handle_fork_read<R: AsyncRead + Unpin>(
    mut reader: R,
    cipher: Option<XChaCha20Poly1305>,
    message_sender: UnboundedSender<Message>,
    tcp_server_address: Arc<str>,
    max_processing_consolidation: usize,
    nonce_to_conn_map: Arc<RwLock<FxHashMap<u32, ClientStream>>>,
    fork_queue: Arc<Mutex<VecDeque<UnboundedSender<Message>>>>,
) -> Result<()> {
    let mut ciphertext_buffer = Cursor::new(Vec::new());
    loop {
        let message = read_enciphered_message(&mut reader, &mut ciphertext_buffer, &cipher).await?;

        match message {
            Message::AddNonce(nonce) => {
                let stream = match TcpStream::connect(tcp_server_address.as_ref()).await {
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
                spawn(handle_write(
                    writer,
                    write_receiver,
                    max_processing_consolidation,
                ));

                let message_sender = select_first_from_deque_appending_to_back_passthrough(
                    &mut *fork_queue.lock().await,
                );

                nonce_to_conn_map.write().await.insert(
                    nonce,
                    ClientStream {
                        _read_drop_guard: AbortOnDropHandle::new(spawn(handle_mc_proxy_read(
                            reader,
                            nonce,
                            message_sender.clone(),
                            nonce_to_conn_map.clone(),
                        ))),
                        write_sender,
                    },
                );
            }
            Message::RemoveNonce(nonce) => {
                nonce_to_conn_map.write().await.remove(&nonce);
            }
            Message::Message { nonce, data } => {
                let read = nonce_to_conn_map.read().await;
                let Some(stream) = read.get(&nonce) else {
                    continue;
                };

                stream.write_sender.send(data)?;
            }
        }
    }
}

#[inline]
pub fn create_fork<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    writer: W,
    max_processing_consolidation: usize,
    cipher: &Option<XChaCha20Poly1305>,
    tcp_server_address: Arc<str>,
    nonce_to_conn_map: Arc<RwLock<FxHashMap<u32, ClientStream>>>,
    fork_queue: Arc<Mutex<VecDeque<UnboundedSender<Message>>>>,
) -> (
    UnboundedSender<Message>,
    impl Future<Output = Result<()>> + use<R, W>,
    impl Future<Output = Result<()>> + use<R, W>,
) {
    let (message_sender, message_receiver) = unbounded_channel();

    (
        message_sender.clone(),
        handle_fork_read(
            reader,
            cipher.clone(),
            message_sender,
            tcp_server_address,
            max_processing_consolidation,
            nonce_to_conn_map,
            fork_queue,
        ),
        handle_fork_write(
            writer,
            message_receiver,
            cipher.clone(),
            max_processing_consolidation,
        ),
    )
}
