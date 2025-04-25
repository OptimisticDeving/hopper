use std::io::Cursor;

use anyhow::{Result, anyhow};
use chacha20poly1305::{XChaCha20Poly1305, aead::Aead};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use rand::{Rng, RngCore, distributions::Standard, rngs::OsRng, thread_rng};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy};
use x25519_dalek::PublicKey;

use crate::{
    key::CRYPT_NONCE_LEN,
    msg::Message,
    util::{read_exact, read_var_int, write_var_int},
};

#[inline]
pub async fn read_public_key_and_nonce<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<(PublicKey, u64)> {
    Ok((
        PublicKey::from(read_exact::<PUBLIC_KEY_LENGTH, _>(&mut reader).await?),
        reader.read_u64().await?,
    ))
}

#[inline]
pub async fn read_enciphered_message<R: AsyncRead + Unpin>(
    mut reader: R,
    mut ciphertext_buffer: &mut Cursor<Vec<u8>>,
    cipher: &Option<XChaCha20Poly1305>,
) -> Result<Message> {
    if let Some(cipher) = cipher {
        ciphertext_buffer.set_position(0);

        let crypt_nonce = read_exact::<CRYPT_NONCE_LEN, _>(&mut reader).await?;
        let ciphertext_len = read_var_int(&mut reader).await?;
        copy(
            &mut ((&mut reader).take(ciphertext_len.try_into()?)),
            &mut ciphertext_buffer,
        )
        .await?;

        let plaintext = cipher
            .decrypt(
                &crypt_nonce.into(),
                &ciphertext_buffer.get_ref()[..ciphertext_buffer.position() as usize],
            )
            .map_err(|e| anyhow!("{e}"))?;
        Message::read(&mut Cursor::new(plaintext)).await
    } else {
        Message::read(reader).await
    }
}

#[inline]
pub async fn write_packet<W: AsyncWrite + Unpin>(
    mut writer: W,
    cipher: &Option<XChaCha20Poly1305>,
    mut plaintext_buffer: &mut Cursor<Vec<u8>>,
    nonce_buffer: &mut [u8; CRYPT_NONCE_LEN],
    message: &Message,
) -> Result<()> {
    if let Some(cipher) = cipher {
        plaintext_buffer.set_position(0);
        message.write(&mut plaintext_buffer).await?;

        thread_rng().fill_bytes(nonce_buffer);
        writer.write_all(&*nonce_buffer).await?;

        let enciphered = cipher
            .encrypt(
                (&*nonce_buffer).into(),
                &plaintext_buffer.get_ref()[..plaintext_buffer.position() as usize],
            )
            .map_err(|e| anyhow!("{e}"))?;
        write_var_int(&mut writer, enciphered.len().try_into()?).await?;
        writer.write_all(&enciphered).await?;
    } else {
        message.write(&mut writer).await?;
    }

    writer.flush().await?;

    Ok(())
}

#[inline]
pub async fn write_public_key_and_nonce<W: AsyncWrite + Unpin>(
    mut writer: W,
    public_key: &PublicKey,
) -> Result<u64> {
    writer.write_all(public_key.as_bytes()).await?;

    let nonce: u64 = OsRng.sample(Standard);
    writer.write_all(&nonce.to_be_bytes()).await?;
    Ok(nonce)
}
