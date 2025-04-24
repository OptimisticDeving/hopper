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

pub struct VerifierAndEncipherer {
    pub our_ed25519: SigningKey,
    pub their_ed25519: VerifyingKey,
}

impl VerifierAndEncipherer {
    #[inline]
    pub async fn generate(
        our_key: &Path,
        our_public_key: &Path,
        peer_key: &Path,
        rng: &mut OsRng,
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
        })
    }

    #[inline]
    pub fn verify(
        &self,
        signature: &Signature,
        our_secret: EphemeralSecret,
        public_key: &PublicKey,
    ) -> Result<XChaCha20Poly1305> {
        self.their_ed25519
            .verify_strict(public_key.as_bytes(), &signature)?;
        Ok(XChaCha20Poly1305::new(
            our_secret.diffie_hellman(public_key).as_bytes().into(),
        ))
    }

    #[inline]
    pub fn sign(&self, public_key: &PublicKey) -> Signature {
        self.our_ed25519.clone().sign(public_key.as_bytes())
    }
}
