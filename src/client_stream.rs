use std::{convert::Infallible, io::Cursor, sync::Arc};

use anyhow::Result;
use chacha20poly1305::XChaCha20Poly1305;
use rustc_hash::FxHashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy},
    sync::{
        RwLock,
        mpsc::{UnboundedReceiver, UnboundedSender},
    },
};
use tokio_util::task::AbortOnDropHandle;
use tracing::info;
use x25519_dalek::PublicKey;

use crate::{
    SPECIAL_PACKET_ID,
    key::CRYPT_NONCE_LEN,
    msg::Message,
    stream::{write_packet, write_public_key_and_nonce},
    util::{read_var_int, write_var_int},
};

#[inline]
pub async fn send_special_packet<W: AsyncWrite + Unpin>(
    mut writer: W,
    public_key: &PublicKey,
) -> Result<u64> {
    let mut body = Vec::new();
    write_var_int(&mut body, SPECIAL_PACKET_ID).await?;
    let timestamp = write_public_key_and_nonce(&mut body, public_key).await?;

    write_var_int(&mut writer, body.len().try_into()?).await?;
    copy(&mut Cursor::new(&mut body), &mut writer).await?;
    writer.flush().await?;

    Ok(timestamp)
}

#[inline]
pub async fn start_writing_messages<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: UnboundedReceiver<Message>,
    cipher: Option<XChaCha20Poly1305>,
    max_processing_consoldiation: usize,
) -> Result<()> {
    let mut nonce = [0u8; CRYPT_NONCE_LEN];
    let mut plaintext_buffer = Cursor::new(Vec::new());
    let mut message_buffer = Vec::new();

    loop {
        message_buffer.clear();

        let received_messages = receiver
            .recv_many(&mut message_buffer, max_processing_consoldiation)
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
pub async fn handle_mc_proxy_read<R: AsyncRead + Unpin>(
    reader: R,
    nonce: u32,
    message_sender: UnboundedSender<Message>,
    nonce_to_conn_map: Arc<
        RwLock<FxHashMap<u32, (AbortOnDropHandle<Result<()>>, UnboundedSender<Vec<u8>>)>>,
    >,
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
    max_processing_consoldiation: usize,
) -> Result<()> {
    let mut packet_buffer = Vec::new();

    loop {
        packet_buffer.clear();

        let received_packets = receiver
            .recv_many(&mut packet_buffer, max_processing_consoldiation)
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
