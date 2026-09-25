//! Encryption for webhook signing secrets at rest.
//!
//! Secrets are sealed with ChaCha20-Poly1305 under `ZBIERAK_SECRET_KEY` and
//! stored as `v1:<nonce>:<ciphertext>` (Base64, unpadded URL-safe). The key
//! lives outside the database so it can be rotated independently; rotation of
//! existing rows is currently manual (re-create the endpoint).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;

use crate::{AppError, AppResult};

const VERSION: &str = "v1";
const NONCE_BYTES: usize = 12;
const KEY_BYTES: usize = 32;

/// Decodes the configured master key from its Base64 form.
///
/// # Errors
///
/// Returns an error when the input is not Base64 or does not decode to
/// exactly 32 bytes.
pub fn parse_key(raw: &str) -> AppResult<[u8; KEY_BYTES]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw.trim()))
        .map_err(|_| {
            AppError::Config("ZBIERAK_SECRET_KEY must be 32 bytes of Base64 data".into())
        })?;
    decoded.try_into().map_err(|_| {
        AppError::Config(format!(
            "ZBIERAK_SECRET_KEY must decode to {KEY_BYTES} bytes"
        ))
    })
}

/// Generates a fresh Base64 master key for operators.
#[must_use]
pub fn generate_key() -> String {
    let mut key = [0_u8; KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    URL_SAFE_NO_PAD.encode(key)
}

fn seal(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad: VERSION.as_bytes(),
            },
        )
        .map_err(|_| AppError::Config("secret encryption failed".into()))
}

fn open(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: VERSION.as_bytes(),
            },
        )
        .map_err(|_| AppError::Config("secret decryption failed: wrong key or corrupt data".into()))
}

/// Encrypts a secret into its stored `v1:<nonce>:<ciphertext>` form.
///
/// # Errors
///
/// Returns an error when the underlying cipher fails, which indicates a
/// broken build or environment rather than caller input.
pub fn encrypt(key: &[u8; KEY_BYTES], plaintext: &str) -> AppResult<String> {
    let mut nonce = [0_u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = seal(key, &nonce, plaintext.as_bytes())?;
    Ok(format!(
        "{VERSION}:{}:{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

/// Decrypts a stored secret, validating the version prefix.
///
/// # Errors
///
/// Returns an error for unsupported encodings, corrupt nonce or ciphertext
/// data, decryption failures (wrong key), and non-UTF-8 plaintext.
pub fn decrypt(key: &[u8; KEY_BYTES], stored: &str) -> AppResult<String> {
    // The exact shape is `version:nonce:ciphertext`; anything else is
    // rejected up front instead of defaulted field by field.
    let [version, nonce_b64, ciphertext_b64] = stored.split(':').collect::<Vec<_>>()[..] else {
        return Err(AppError::Config("unsupported secret encoding".into()));
    };
    if version != VERSION {
        return Err(AppError::Config("unsupported secret encoding".into()));
    }
    let nonce: [u8; NONCE_BYTES] = URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| AppError::Config("corrupt secret nonce".into()))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext_b64)
        .map_err(|_| AppError::Config("corrupt secret ciphertext".into()))?;
    let plaintext = open(key, &nonce, &ciphertext)?;
    String::from_utf8(plaintext)
        .map_err(|_| AppError::Config("decrypted secret is not UTF-8".into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::*;

    #[test]
    fn round_trip_preserves_the_secret() {
        let key = generate_key();
        let parsed = parse_key(&key).unwrap();
        let stored = encrypt(&parsed, "correct horse battery staple").unwrap();
        assert!(stored.starts_with("v1:"));
        assert_ne!(stored, "correct horse battery staple");
        assert!(!stored.contains("staple"));
        assert_eq!(
            decrypt(&parsed, &stored).unwrap(),
            "correct horse battery staple"
        );
    }

    #[test]
    fn wrong_key_or_corruption_fails() {
        let parsed = parse_key(&generate_key()).unwrap();
        let other = parse_key(&generate_key()).unwrap();
        let stored = encrypt(&parsed, "a-very-secret-value").unwrap();
        assert!(decrypt(&other, &stored).is_err());
        assert!(decrypt(&parsed, &format!("{stored}zzz")).is_err());
        assert!(decrypt(&parsed, "v2:aa:bb").is_err());
        assert!(decrypt(&parsed, "v1:nonsense:also").is_err());
    }

    #[test]
    fn parse_key_rejects_bad_input() {
        assert!(parse_key("not base64 !!!").is_err());
        assert!(parse_key(&URL_SAFE_NO_PAD.encode([0_u8; 16])).is_err());
        assert!(parse_key(&generate_key()).is_ok());
    }
}
