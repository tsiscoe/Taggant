//! Cryptographic Core for **Taggant** (`taggant v0.1.0`):
//! - `Argon2id` (`64 MiB, t=3, p=4`) + `HKDF-SHA256` vault key hierarchy
//! - `XChaCha20-Poly1305` authenticated vault encryption with `ZeroizeOnDrop`
//! - `X25519` asymmetric `TaggantPubKey` / `TaggantAutopsyKey` custody
//! - Constant-time `GF(2^255 - 19)` arithmetic, uniform two-branch `Elligator2`, and `60B`/`64B` capsules

pub mod capsule;
pub mod elligator;
pub mod fe25519;

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;

/// 256-bit Master Seed derived from user passphrase via `Argon2id`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed([u8; KEY_LEN]);

/// Domain-separated 256-bit subkeys expanded from [`MasterSeed`] via `HKDF-SHA256`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultSubkeys {
    pub vault_key: [u8; KEY_LEN],
    pub mac_key: [u8; KEY_LEN],
    pub verifier: [u8; KEY_LEN],
}

/// Asymmetric Taggant keypair: only `autopsy_sk` can decrypt and verify canaries;
/// `pub_key` can safely live on untrusted hosts to mint decoy tokens.
pub struct TaggantKeypair {
    pub autopsy_sk: StaticSecret,
    pub pub_key: PublicKey,
}

impl TaggantKeypair {
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let autopsy_sk = StaticSecret::from(raw);
        raw.zeroize();
        let pub_key = PublicKey::from(&autopsy_sk);
        Self {
            autopsy_sk,
            pub_key,
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let autopsy_sk = StaticSecret::from(bytes);
        let pub_key = PublicKey::from(&autopsy_sk);
        Self {
            autopsy_sk,
            pub_key,
        }
    }

    pub fn encode_pubkey_b64(&self) -> String {
        format!(
            "taggant-pub-v1:{}",
            BASE64_STD.encode(self.pub_key.as_bytes())
        )
    }
}

/// Parse a `taggant-pub-v1:<base64>`, bare 32-byte Base64, or 64-char hex public key.
pub fn parse_public_key(spec: &str) -> Result<PublicKey> {
    let trimmed = spec.trim();
    let body = trimmed.strip_prefix("taggant-pub-v1:").unwrap_or(trimmed);

    if body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit()) {
        let raw = hex::decode(body).map_err(|e| anyhow!("invalid hex public key: {e}"))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("public key hex must decode to 32 bytes"))?;
        return Ok(PublicKey::from(arr));
    }

    let raw = BASE64_STD
        .decode(body)
        .map_err(|e| anyhow!("invalid Base64 public key: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("public key Base64 must decode to 32 bytes"))?;
    Ok(PublicKey::from(arr))
}

/// Parse a 64-char hex or Base64 raw `TaggantAutopsyKey` secret key.
pub fn parse_secret_key(spec: &str) -> Result<StaticSecret> {
    let trimmed = spec.trim();
    let body = trimmed.strip_prefix("taggant-sec-v1:").unwrap_or(trimmed);

    let mut arr = if body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit()) {
        let raw = hex::decode(body).map_err(|e| anyhow!("invalid hex secret key: {e}"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("secret key hex must decode to 32 bytes"))?;
        bytes
    } else {
        let raw = BASE64_STD
            .decode(body)
            .map_err(|e| anyhow!("invalid Base64 secret key: {e}"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("secret key Base64 must decode to 32 bytes"))?;
        bytes
    };

    let sk = StaticSecret::from(arr);
    arr.zeroize();
    Ok(sk)
}

impl MasterSeed {
    /// Derive a 256-bit `MasterSeed` using production `Argon2id` parameters (`64 MiB, t=3, p=4`).
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid Argon2id params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Fast `Argon2id` derivation (`8 MiB, t=1, p=1`) strictly for automated test suites.
    pub fn derive_fast_for_test(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(8 * 1024, 1, 1, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid test Argon2id params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("test Argon2id derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Expand `vault_key`, `mac_key`, and `verifier` via `HKDF-SHA256`.
    pub fn derive_subkeys(&self, salt: &[u8; SALT_LEN]) -> Result<VaultSubkeys> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut vault_key = [0u8; KEY_LEN];
        let mut mac_key = [0u8; KEY_LEN];
        let mut verifier = [0u8; KEY_LEN];

        hk.expand(b"taggant-v1-vault-key", &mut vault_key)
            .map_err(|_| anyhow!("HKDF expand failed for vault_key"))?;
        hk.expand(b"taggant-v1-mac-key", &mut mac_key)
            .map_err(|_| anyhow!("HKDF expand failed for mac_key"))?;
        hk.expand(b"taggant-v1-verifier", &mut verifier)
            .map_err(|_| anyhow!("HKDF expand failed for verifier"))?;

        Ok(VaultSubkeys {
            vault_key,
            mac_key,
            verifier,
        })
    }
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Constant-time 32-byte equality check (`CWE-208`).
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Encrypt arbitrary bytes under `XChaCha20-Poly1305` with fresh 192-bit nonce and AAD.
/// Layout: `nonce[24] || ciphertext+tag`.
pub fn aead_encrypt(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key"))?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;
    let mut out = Vec::with_capacity(XNONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt `nonce[24] || ciphertext+tag` under `XChaCha20-Poly1305` and verify AAD.
pub fn aead_decrypt(key: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < XNONCE_LEN + 16 {
        return Err(anyhow!("AEAD blob too short"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&blob[..XNONCE_LEN]),
            Payload {
                msg: &blob[XNONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| anyhow!("AEAD authentication failed (tampered vault row or wrong key)"))
}

/// Compute a keyed `BLAKE3` 64-char hex blind index for constant-time DB lookups.
pub fn keyed_blake3_hex(mac_key: &[u8; KEY_LEN], domain: &str, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(domain.as_bytes());
    hasher.update(b"|");
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Compute an unkeyed domain-separated `BLAKE3` hash (used for tamper-evident Merkle chain links).
pub fn blake3_hash_hex(parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().to_hex().to_string()
}
