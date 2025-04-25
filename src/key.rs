use std::path::Path;

use anyhow::{Result, bail};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use ed25519::{Signature, signature::SignerMut};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use tokio::fs::{try_exists, write};
use tracing::info;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::util::read_exact_file;

pub const CRYPT_NONCE_LEN: usize = 24;
pub const SIGN_MESSAGE_SIZE: usize = (8 * 2) + (32 * 2);

pub struct VerifierAndEncipherer {
    pub our_ed25519: SigningKey,
    pub their_ed25519: VerifyingKey,
    pub is_client: bool,
}

impl VerifierAndEncipherer {
    #[inline]
    pub fn create_message(
        client_nonce: u64,
        server_nonce: u64,
        client_public_key: &PublicKey,
        server_public_key: &PublicKey,
    ) -> [u8; SIGN_MESSAGE_SIZE] {
        let mut message = [0u8; SIGN_MESSAGE_SIZE];

        message[0..8].copy_from_slice(&client_nonce.to_be_bytes());
        message[8..16].copy_from_slice(&server_nonce.to_be_bytes());
        message[16..48].copy_from_slice(client_public_key.as_bytes());
        message[48..].copy_from_slice(server_public_key.as_bytes());

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
    pub fn peer_verify(
        &self,
        signature: &Signature,
        our_secret: EphemeralSecret,
        client_nonce: u64,
        server_nonce: u64,
        client_public_key: &PublicKey,
        server_public_key: &PublicKey,
        do_encryption: bool,
    ) -> Result<Option<XChaCha20Poly1305>> {
        let message = Self::create_message(
            client_nonce,
            server_nonce,
            client_public_key,
            server_public_key,
        );

        self.their_ed25519.verify_strict(&message, &signature)?;
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
    pub fn sign_and_verify(
        &self,
        client_nonce: u64,
        server_nonce: u64,
        client_public_key: &PublicKey,
        server_public_key: &PublicKey,
    ) -> Result<Signature> {
        Ok(self.our_ed25519.clone().sign(&Self::create_message(
            client_nonce,
            server_nonce,
            client_public_key,
            server_public_key,
        )))
    }
}
