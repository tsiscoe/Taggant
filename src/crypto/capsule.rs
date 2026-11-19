//! HPKE-style `64-byte` and compact `60-byte` `Elligator2` provenance capsules.
//!
//! Wire layout (`64B` capsule):
//! - `0..32`: Uniform `Elligator2` ephemeral representative (`repr`)
//! - `32..48`: `ChaCha20-Poly1305` ciphertext of `Provenance16` (`16B`)
//! - `48..64`: `Poly1305` authentication tag (`16B`)
//!
//! Compact layout (`60B` capsule for `github_pat_`):
//! - `0..32`: Uniform `Elligator2` ephemeral representative (`repr`)
//! - `32..44`: `ChaCha20-Poly1305` ciphertext of `Provenance12` (`12B`)
//! - `44..60`: `Poly1305` authentication tag (`16B`)

use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::elligator::{elligator2_decode, elligator2_generate_ephemeral};

pub const CAPSULE64_LEN: usize = 64;
pub const CAPSULE60_LEN: usize = 60;
const CAPSULE_VERSION_1: u8 = 0x10;

/// Metadata inputs used to mint an offline self-attributing canary capsule.
#[derive(Debug, Clone)]
pub struct ProvenanceContext {
    pub profile_id: String,
    pub kind_code: u8,
    pub epoch_minutes: u32,
    pub host: String,
    pub path: String,
    pub branch: String,
}

/// Decoded offline provenance extracted strictly from a leaked token without DB state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedProvenance {
    pub version: u8,
    pub kind_code: u8,
    pub epoch_minutes: u32,
    pub host_tag_hex: String,
    pub path_tag_hex: String,
    pub branch_tag_hex: String,
    pub compact_mode: bool,
}

impl ProvenanceContext {
    /// Compute the deterministic short `BLAKE3` tags stored inside a capsule.
    pub fn compute_tags(&self) -> ([u8; 3], [u8; 4], [u8; 4]) {
        let h = *blake3::hash(self.host.as_bytes()).as_bytes();
        let p = *blake3::hash(self.path.as_bytes()).as_bytes();
        let b = *blake3::hash(self.branch.as_bytes()).as_bytes();
        (
            [h[0], h[1], h[2]],
            [p[0], p[1], p[2], p[3]],
            [b[0], b[1], b[2], b[3]],
        )
    }

    pub fn pack16(&self) -> [u8; 16] {
        let (ht, pt, bt) = self.compute_tags();
        let mut out = [0u8; 16];
        out[0] = CAPSULE_VERSION_1 | (self.kind_code & 0x0f);
        out[1..5].copy_from_slice(&self.epoch_minutes.to_le_bytes());
        out[5..8].copy_from_slice(&ht);
        out[8..12].copy_from_slice(&pt);
        out[12..16].copy_from_slice(&bt);
        out
    }

    pub fn pack12(&self) -> [u8; 12] {
        let (ht, pt, bt) = self.compute_tags();
        let mut out = [0u8; 12];
        out[0] = CAPSULE_VERSION_1 | (self.kind_code & 0x0f);
        out[1..5].copy_from_slice(&self.epoch_minutes.to_le_bytes());
        out[5..7].copy_from_slice(&ht[..2]);
        out[7..10].copy_from_slice(&pt[..3]);
        out[10..12].copy_from_slice(&bt[..2]);
        out
    }
}

fn derive_capsule_key_nonce(
    shared_secret: &[u8; 32],
    repr: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], [u8; 12])> {
    let hk = Hkdf::<Sha256>::new(Some(repr), shared_secret);
    let mut okm = [0u8; 44];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed for Taggant capsule"))?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[0..32]);
    nonce.copy_from_slice(&okm[32..44]);
    okm.zeroize();
    Ok((key, nonce))
}

fn is_all_zero_32(bytes: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

/// Seal a 16-byte provenance payload into a 64-byte uniform `Elligator2` capsule using ONLY
/// the recipient's `TaggantPubKey`.
pub fn seal_capsule_64<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_key: &PublicKey,
    ctx: &ProvenanceContext,
) -> Result<[u8; CAPSULE64_LEN]> {
    let (eph_sk, repr) = elligator2_generate_ephemeral(rng);
    let shared = eph_sk.diffie_hellman(pub_key);
    let mut shared_bytes = *shared.as_bytes();
    if is_all_zero_32(&shared_bytes) {
        return Err(anyhow!(
            "rejected low-order ECDH shared secret during capsule seal"
        ));
    }

    let (mut key, mut nonce) =
        derive_capsule_key_nonce(&shared_bytes, &repr, b"taggant-v1-capsule64")?;
    shared_bytes.zeroize();

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key"))?;
    let mut plaintext = ctx.pack16();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: ctx.profile_id.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("AEAD encryption failed for 64B capsule"))?;

    key.zeroize();
    nonce.zeroize();
    plaintext.zeroize();

    if ct.len() != 32 {
        return Err(anyhow!(
            "unexpected 64B capsule ciphertext length: {}",
            ct.len()
        ));
    }
    let mut out = [0u8; CAPSULE64_LEN];
    out[0..32].copy_from_slice(&repr);
    out[32..64].copy_from_slice(&ct);
    Ok(out)
}

/// Decrypt and authenticate a 64-byte `Elligator2` capsule strictly offline using `autopsy_sk`.
pub fn open_capsule_64(
    autopsy_sk: &StaticSecret,
    profile_id: &str,
    capsule: &[u8; CAPSULE64_LEN],
) -> Result<DecodedProvenance> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&capsule[0..32]);
    let eph_u = elligator2_decode(&repr);
    let shared = autopsy_sk.diffie_hellman(&PublicKey::from(eph_u));
    let mut shared_bytes = *shared.as_bytes();
    if is_all_zero_32(&shared_bytes) {
        return Err(anyhow!("rejected low-order ECDH point in 64B capsule"));
    }

    let (mut key, mut nonce) =
        derive_capsule_key_nonce(&shared_bytes, &repr, b"taggant-v1-capsule64")?;
    shared_bytes.zeroize();

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key"))?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &capsule[32..64],
                aad: profile_id.as_bytes(),
            },
        )
        .map_err(|_| {
            anyhow!("capsule authentication failed (invalid key, profile, or tampered token)")
        })?;

    key.zeroize();
    nonce.zeroize();

    if pt.len() != 16 {
        return Err(anyhow!("corrupt 64B capsule plaintext length"));
    }
    let ver = pt[0] >> 4;
    if ver != (CAPSULE_VERSION_1 >> 4) {
        return Err(anyhow!("unsupported Taggant capsule version {ver}"));
    }
    let kind_code = pt[0] & 0x0f;
    let epoch_minutes = u32::from_le_bytes([pt[1], pt[2], pt[3], pt[4]]);

    Ok(DecodedProvenance {
        version: ver,
        kind_code,
        epoch_minutes,
        host_tag_hex: hex::encode(&pt[5..8]),
        path_tag_hex: hex::encode(&pt[8..12]),
        branch_tag_hex: hex::encode(&pt[12..16]),
        compact_mode: false,
    })
}

/// Seal a 12-byte provenance payload into a compact 60-byte `Elligator2` capsule (`github_pat_`).
pub fn seal_capsule_60<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_key: &PublicKey,
    ctx: &ProvenanceContext,
) -> Result<[u8; CAPSULE60_LEN]> {
    let (eph_sk, repr) = elligator2_generate_ephemeral(rng);
    let shared = eph_sk.diffie_hellman(pub_key);
    let mut shared_bytes = *shared.as_bytes();
    if is_all_zero_32(&shared_bytes) {
        return Err(anyhow!(
            "rejected low-order ECDH shared secret during 60B capsule seal"
        ));
    }

    let (mut key, mut nonce) =
        derive_capsule_key_nonce(&shared_bytes, &repr, b"taggant-v1-capsule60")?;
    shared_bytes.zeroize();

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key"))?;
    let mut plaintext = ctx.pack12();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: ctx.profile_id.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("AEAD encryption failed for 60B capsule"))?;

    key.zeroize();
    nonce.zeroize();
    plaintext.zeroize();

    if ct.len() != 28 {
        return Err(anyhow!(
            "unexpected 60B capsule ciphertext length: {}",
            ct.len()
        ));
    }
    let mut out = [0u8; CAPSULE60_LEN];
    out[0..32].copy_from_slice(&repr);
    out[32..60].copy_from_slice(&ct);
    Ok(out)
}

/// Decrypt and authenticate a 60-byte compact `Elligator2` capsule strictly offline.
pub fn open_capsule_60(
    autopsy_sk: &StaticSecret,
    profile_id: &str,
    capsule: &[u8; CAPSULE60_LEN],
) -> Result<DecodedProvenance> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&capsule[0..32]);
    let eph_u = elligator2_decode(&repr);
    let shared = autopsy_sk.diffie_hellman(&PublicKey::from(eph_u));
    let mut shared_bytes = *shared.as_bytes();
    if is_all_zero_32(&shared_bytes) {
        return Err(anyhow!("rejected low-order ECDH point in 60B capsule"));
    }

    let (mut key, mut nonce) =
        derive_capsule_key_nonce(&shared_bytes, &repr, b"taggant-v1-capsule60")?;
    shared_bytes.zeroize();

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key"))?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &capsule[32..60],
                aad: profile_id.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("compact capsule authentication failed"))?;

    key.zeroize();
    nonce.zeroize();

    if pt.len() != 12 {
        return Err(anyhow!("corrupt 60B capsule plaintext length"));
    }
    let ver = pt[0] >> 4;
    if ver != (CAPSULE_VERSION_1 >> 4) {
        return Err(anyhow!("unsupported Taggant compact capsule version {ver}"));
    }
    let kind_code = pt[0] & 0x0f;
    let epoch_minutes = u32::from_le_bytes([pt[1], pt[2], pt[3], pt[4]]);

    Ok(DecodedProvenance {
        version: ver,
        kind_code,
        epoch_minutes,
        host_tag_hex: hex::encode(&pt[5..7]),
        path_tag_hex: hex::encode(&pt[7..10]),
        branch_tag_hex: hex::encode(&pt[10..12]),
        compact_mode: true,
    })
}
