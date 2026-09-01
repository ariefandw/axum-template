//! Cryptographic primitives shared across the platform.
//!
//! Everything security-sensitive funnels through here so the choices are made
//! once and can be audited in one place: token hashing, URL signing, encryption
//! of third-party credentials at rest, and a `Secret` wrapper that keeps
//! credentials out of logs and `Debug` output.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore, distr::Alphanumeric};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 12;

/// A string that must never reach a log line, a `Debug` dump, or an error body.
///
/// `Debug` and `Display` both redact. The inner value is reachable only through
/// [`Secret::expose`], which makes every read site greppable.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the underlying secret. Every call site is an intentional disclosure.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Lowercase hex SHA-256. Used for every at-rest token digest so that a database
/// leak does not hand over usable session, reset, or verification tokens.
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A URL-safe random token drawn from the OS CSPRNG.
pub fn random_token(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Constant-time comparison, for the rare case where a secret is compared
/// directly rather than by indexed hash lookup.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Sign a canonical string with the URL-signing key. Used to make presigned
/// storage URLs genuinely unforgeable rather than merely opaque.
pub fn sign(key: &[u8], message: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Verify a signature produced by [`sign`], in constant time.
pub fn verify_signature(key: &[u8], message: &str, signature: &str) -> bool {
    let Ok(provided) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.verify_slice(&provided).is_ok()
}

/// Encrypt a value for storage with ChaCha20-Poly1305.
///
/// The random nonce is prepended to the ciphertext and the whole thing is
/// base64url encoded, so a single `TEXT` column round-trips it.
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, AppError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    // A fresh random nonce per message: reusing one under the same key would
    // destroy the confidentiality guarantee entirely.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| AppError::Internal("Failed to encrypt value".into()))?;

    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(combined))
}

/// Reverse of [`encrypt`].
pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Secret, AppError> {
    let combined = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::Internal("Stored ciphertext is not valid base64".into()))?;

    if combined.len() <= NONCE_LEN {
        return Err(AppError::Internal("Stored ciphertext is truncated".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| AppError::Internal("Failed to decrypt value".into()))?;

    String::from_utf8(plaintext)
        .map(Secret::new)
        .map_err(|_| AppError::Internal("Decrypted value is not valid UTF-8".into()))
}

/// Generate a fresh 32-byte key, base64url encoded, for operators bootstrapping
/// `ENCRYPTION_KEY`.
pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    URL_SAFE_NO_PAD.encode(key)
}

/// Parse an `ENCRYPTION_KEY` supplied as base64url, standard base64, or hex.
pub fn parse_encryption_key(raw: &str) -> Result<[u8; 32], String> {
    let raw = raw.trim();

    // Hex is attempted first: a 64-character hex string is also valid base64,
    // and decoding it as base64 silently yields 48 bytes instead of 32.
    let decoded = hex_decode(raw)
        .or_else(|_| URL_SAFE_NO_PAD.decode(raw))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
        .map_err(|_| "ENCRYPTION_KEY must be base64 or hex encoded".to_string())?;

    if decoded.len() != 32 {
        return Err(format!(
            "ENCRYPTION_KEY must decode to exactly 32 bytes, got {}",
            decoded.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Derive a stable 32-byte key from an existing secret. Development only: it
/// lets a single `JWT_SECRET` bootstrap a working stack, and production refuses
/// to start without a dedicated `ENCRYPTION_KEY`.
pub fn derive_key_from_secret(secret: &str, context: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn hex_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if input.len() % 2 != 0 || !input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(base64::DecodeError::InvalidLength(input.len()));
    }
    Ok((0..input.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_never_reveals_itself_in_debug_or_display() {
        let secret = Secret::new("super-secret-signing-key");
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert!(!format!("{secret:?} {secret}").contains("super-secret"));
        assert_eq!(secret.expose(), "super-secret-signing-key");
    }

    #[test]
    fn encryption_round_trips_and_rejects_tampering() {
        let key = [7u8; 32];
        let sealed = encrypt(&key, "ya29.provider-access-token").unwrap();
        assert!(!sealed.contains("ya29"));
        assert_eq!(
            decrypt(&key, &sealed).unwrap().expose(),
            "ya29.provider-access-token"
        );

        // A different key must not open it.
        assert!(decrypt(&[8u8; 32], &sealed).is_err());

        // Nonce reuse must not happen: same plaintext, different ciphertext.
        assert_ne!(sealed, encrypt(&key, "ya29.provider-access-token").unwrap());
    }

    #[test]
    fn signatures_verify_and_reject_forgery() {
        let key = b"url-signing-key";
        let sig = sign(key, "GET\n/files/abc\n1700000000");
        assert!(verify_signature(key, "GET\n/files/abc\n1700000000", &sig));
        // Any change to the signed message invalidates it.
        assert!(!verify_signature(key, "GET\n/files/xyz\n1700000000", &sig));
        assert!(!verify_signature(key, "GET\n/files/abc\n1799999999", &sig));
        assert!(!verify_signature(
            b"other-key",
            "GET\n/files/abc\n1700000000",
            &sig
        ));
    }

    #[test]
    fn encryption_key_parses_from_base64_and_hex() {
        // A 64-char hex string is also valid base64; decoding it as base64 would
        // yield 48 bytes, so hex must win.
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let from_hex = parse_encryption_key(hex).unwrap();
        assert_eq!(from_hex.len(), 32);
        assert_eq!(&from_hex[..4], &[0x00, 0x11, 0x22, 0x33]);

        let b64 = generate_encryption_key();
        assert_eq!(parse_encryption_key(&b64).unwrap().len(), 32);

        // Standard base64 with padding, as `openssl rand -base64 32` emits.
        assert_eq!(
            parse_encryption_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
                .unwrap()
                .len(),
            32
        );

        assert!(parse_encryption_key("too-short").is_err());
        assert!(parse_encryption_key("00112233").is_err());
    }

    #[test]
    fn sha256_is_stable_and_hex_encoded() {
        let h = sha256_hex("token");
        assert_eq!(h.len(), 64);
        assert_eq!(h, sha256_hex("token"));
        assert_ne!(h, sha256_hex("token "));
    }
}
