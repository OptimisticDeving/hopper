use std::path::Path;

use anyhow::{Result, bail};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use ed25519::{Signature, signature::SignerMut};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use tokio::fs::{try_exists, write};
use tracing::info;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{stream::CryptCombination, util::read_exact_file};

pub const CRYPT_NONCE_LEN: usize = 24;
pub const TRUE_STREAM_MESSAGE_SIZE: usize = (8 * 2) + (32 * 2);
pub const FORK_STREAM_MESSAGE_SIZE: usize = (8 * 3) + 32;

pub struct VerifierAndEncipherer {
    pub our_ed25519: SigningKey,
    pub their_ed25519: VerifyingKey,
    pub is_client: bool,
}

impl VerifierAndEncipherer {
    #[inline]
    pub fn true_stream_message(
        client_nonce: u64,
        server_nonce: u64,
        client_public_key: &PublicKey,
        server_public_key: &PublicKey,
    ) -> [u8; TRUE_STREAM_MESSAGE_SIZE] {
        let mut message = [0u8; TRUE_STREAM_MESSAGE_SIZE];

        message[0..8].copy_from_slice(&client_nonce.to_be_bytes());
        message[8..16].copy_from_slice(&server_nonce.to_be_bytes());
        message[16..48].copy_from_slice(client_public_key.as_bytes());
        message[48..].copy_from_slice(server_public_key.as_bytes());

        message
    }

    #[inline]
    pub fn fork_stream_message(
        combination: &CryptCombination,
        fork_nonce: u64,
        stream_nonce: u64,
    ) -> [u8; FORK_STREAM_MESSAGE_SIZE] {
        let mut message = [0u8; FORK_STREAM_MESSAGE_SIZE];

        message[0..8].copy_from_slice(&combination.combined_nonces.to_be_bytes());
        message[8..40].copy_from_slice(&combination.combined_public_keys);
        message[40..48].copy_from_slice(&fork_nonce.to_be_bytes());
        message[48..].copy_from_slice(&stream_nonce.to_be_bytes());

        message
    }

    #[inline]
    pub async fn generate(
        our_key: &Path,
        our_public_key: &Path,
        peer_key: &Path,
        rng: &mut OsRng,
        is_client: bool,
    ) -> Result<Self> {
        let signing_key = if !try_exists(our_key).await? {
            info!("couldn't find private key, generating now");

            let signing_key = SigningKey::generate(rng);
            write(our_key, signing_key.as_bytes()).await?;
            write(our_public_key, signing_key.verifying_key().as_bytes()).await?;
            signing_key
        } else {
            SigningKey::from_bytes(&read_exact_file::<SECRET_KEY_LENGTH>(our_key).await?)
        };

        let verifying_key = if !try_exists(peer_key).await? {
            bail!("couldn't find peer public key")
        } else {
            VerifyingKey::from_bytes(&read_exact_file::<PUBLIC_KEY_LENGTH>(peer_key).await?)?
        };

        Ok(Self {
            our_ed25519: signing_key,
            their_ed25519: verifying_key,
            is_client,
        })
    }

    #[inline]
    fn peer_verify(&self, signature: &Signature, msg: &[u8]) -> Result<()> {
        self.their_ed25519.verify_strict(&msg, &signature)?;
        Ok(())
    }

    #[inline]
    pub fn true_stream_peer_verify(
        &self,
        signature: &Signature,
        our_secret: EphemeralSecret,
        client_nonce: u64,
        server_nonce: u64,
        client_public_key: &PublicKey,
        server_public_key: &PublicKey,
        do_encryption: bool,
    ) -> Result<Option<XChaCha20Poly1305>> {
        let msg = Self::true_stream_message(
            client_nonce,
            server_nonce,
            client_public_key,
            server_public_key,
        );

        self.peer_verify(signature, &msg)?;

        let diffie_hellman = our_secret.diffie_hellman(if self.is_client {
            server_public_key
        } else {
            client_public_key
        });

        Ok(if do_encryption {
            Some(XChaCha20Poly1305::new(diffie_hellman.as_bytes().into()))
        } else {
            None
        })
    }

    #[inline]
    pub fn fork_stream_verify(
        &self,
        signature: &Signature,
        combination: &CryptCombination,
        fork_nonce: u64,
        stream_nonce: u64,
    ) -> Result<()> {
        self.peer_verify(
            signature,
            &Self::fork_stream_message(combination, fork_nonce, stream_nonce),
        )
    }

    #[inline]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.our_ed25519.clone().sign(msg)
    }

    #[inline]
    pub fn true_stream_sign(
        &self,
        client_nonce: u64,
        server_nonce: u64,
        client_public_key: &PublicKey,
        server_public_key: &PublicKey,
    ) -> Signature {
        self.sign(&Self::true_stream_message(
            client_nonce,
            server_nonce,
            client_public_key,
            server_public_key,
        ))
    }

    #[inline]
    pub fn fork_stream_sign(
        &self,
        combination: &CryptCombination,
        fork_nonce: u64,
        stream_nonce: u64,
    ) -> Signature {
        self.sign(&Self::fork_stream_message(
            combination,
            fork_nonce,
            stream_nonce,
        ))
    }
}
