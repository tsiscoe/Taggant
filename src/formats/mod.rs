//! Token bait formatters, fixed-width Base62, tableless IEEE `CRC32`, OpenSSH framing,
//! and multi-pattern leak extractor (`#![forbid(unsafe_code)]`).

use anyhow::{Result, anyhow};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as BASE64_URL},
};
use rand::{CryptoRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::capsule::{
    CAPSULE60_LEN, CAPSULE64_LEN, DecodedProvenance, ProvenanceContext, open_capsule_60,
    open_capsule_64, seal_capsule_60, seal_capsule_64,
};

const BASE62_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE32_UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Supported honeytoken bait profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaitProfile {
    OpenaiProj,
    AnthropicApi,
    GithubPat,
    OpensshKey,
    GithubClassic,
    AwsIamPair,
}

impl BaitProfile {
    pub fn id(self) -> &'static str {
        match self {
            Self::OpenaiProj => "openai-proj",
            Self::AnthropicApi => "anthropic-api",
            Self::GithubPat => "github-pat",
            Self::OpensshKey => "openssh-key",
            Self::GithubClassic => "github-classic",
            Self::AwsIamPair => "aws-iam-pair",
        }
    }

    pub fn kind_code(self) -> u8 {
        match self {
            Self::OpenaiProj => 1,
            Self::AnthropicApi => 2,
            Self::GithubPat => 3,
            Self::OpensshKey => 4,
            Self::GithubClassic => 5,
            Self::AwsIamPair => 6,
        }
    }

    pub fn from_kind_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::OpenaiProj),
            2 => Some(Self::AnthropicApi),
            3 => Some(Self::GithubPat),
            4 => Some(Self::OpensshKey),
            5 => Some(Self::GithubClassic),
            6 => Some(Self::AwsIamPair),
            _ => None,
        }
    }

    pub fn from_str_id(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "openai" | "openai-proj" | "sk-proj" => Ok(Self::OpenaiProj),
            "anthropic" | "anthropic-api" | "sk-ant" => Ok(Self::AnthropicApi),
            "github-pat" | "github_pat" | "pat" => Ok(Self::GithubPat),
            "openssh" | "openssh-key" | "ssh" => Ok(Self::OpensshKey),
            "github-classic" | "ghp" => Ok(Self::GithubClassic),
            "aws" | "aws-iam" | "aws-iam-pair" | "akia" => Ok(Self::AwsIamPair),
            other => Err(anyhow!(
                "unknown bait profile '{other}' (expected openai-proj, anthropic-api, github-pat, openssh-key, github-classic, aws-iam-pair)"
            )),
        }
    }

    pub fn is_tier1_stateless(self) -> bool {
        matches!(
            self,
            Self::OpenaiProj | Self::AnthropicApi | Self::GithubPat | Self::OpensshKey
        )
    }

    pub fn default_env_var(self) -> &'static str {
        match self {
            Self::OpenaiProj => "OPENAI_API_KEY",
            Self::AnthropicApi => "ANTHROPIC_API_KEY",
            Self::GithubPat => "GITHUB_PAT",
            Self::OpensshKey => "DEPLOY_SSH_PRIVATE_KEY",
            Self::GithubClassic => "GITHUB_TOKEN",
            Self::AwsIamPair => "AWS_ACCESS_KEY_ID",
        }
    }
}

/// Output produced when minting a decoy token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintedToken {
    pub profile: BaitProfile,
    pub env_var: String,
    pub primary_secret: String,
    pub secondary_secret: Option<String>,
    pub host_tag_hex: String,
    pub path_tag_hex: String,
    pub branch_tag_hex: String,
    pub epoch_minutes: u32,
}

/// Result of an offline Tier-1 capsule decode (does not require DB state).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatelessAutopsyHit {
    pub profile: BaitProfile,
    pub token_preview: String,
    pub epoch_minutes: u32,
    pub host_tag_hex: String,
    pub path_tag_hex: String,
    pub branch_tag_hex: String,
    pub compact_mode: bool,
}

/// Tableless IEEE 802.3 CRC-32 (`0xEDB88320`).
pub fn ieee_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320u32 & mask);
        }
    }
    !crc
}

/// Encode a big-endian byte slice into a fixed-width Base62 string (`0-9A-Za-z`).
pub fn encode_base62_fixed(bytes: &[u8], width: usize) -> Result<String> {
    let mut digits = vec![0u8; width];
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in &mut digits {
            let val = (*d as u32) * 256 + carry;
            *d = (val % 62) as u8;
            carry = val / 62;
        }
        if carry != 0 {
            return Err(anyhow!("input integer overflows {width}-char Base62 width"));
        }
    }
    let mut out = String::with_capacity(width);
    for &d in digits.iter().rev() {
        out.push(BASE62_ALPHABET[d as usize] as char);
    }
    Ok(out)
}

fn base62_digit(ch: u8) -> Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'A'..=b'Z' => Ok(ch - b'A' + 10),
        b'a'..=b'z' => Ok(ch - b'a' + 36),
        _ => Err(anyhow!("invalid Base62 character '{}'", ch as char)),
    }
}

/// Decode a fixed-width Base62 string back into `out_len` big-endian bytes.
pub fn decode_base62_fixed(input: &str, out_len: usize) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(anyhow!("empty Base62 payload"));
    }
    let mut bytes = vec![0u8; out_len];
    for ch in input.bytes() {
        let mut carry = base62_digit(ch)? as u32;
        for b in bytes.iter_mut().rev() {
            let acc = (*b as u32) * 62 + carry;
            *b = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return Err(anyhow!("Base62 integer exceeds {out_len}-byte capacity"));
        }
    }
    Ok(bytes)
}

fn encode_u32_base62_6(val: u32) -> String {
    let mut v = val;
    let mut chars = [b'0'; 6];
    for c in chars.iter_mut().rev() {
        *c = BASE62_ALPHABET[(v % 62) as usize];
        v /= 62;
    }
    String::from_utf8(chars.to_vec()).unwrap_or_default()
}

/// Validate the IEEE CRC32 checksum embedded in the final 6 chars of a `ghp_` token.
pub fn verify_github_classic_crc(token: &str) -> bool {
    let Some(body) = token.strip_prefix("ghp_") else {
        return false;
    };
    if body.len() != 36 || !body.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let (prefix30, crc6) = body.split_at(30);
    let expected = encode_u32_base62_6(ieee_crc32(prefix30.as_bytes()));
    crc6 == expected
}

fn write_ssh_str(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_ssh_str<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    if *cursor + 4 > input.len() {
        return Err(anyhow!("truncated OpenSSH length prefix"));
    }
    let len = u32::from_be_bytes([
        input[*cursor],
        input[*cursor + 1],
        input[*cursor + 2],
        input[*cursor + 3],
    ]) as usize;
    *cursor += 4;
    if *cursor + len > input.len() {
        return Err(anyhow!("truncated OpenSSH field payload"));
    }
    let slice = &input[*cursor..*cursor + len];
    *cursor += len;
    Ok(slice)
}

fn encode_openssh_ed25519_envelope(capsule: &[u8; CAPSULE64_LEN], comment: &str) -> String {
    let pub_part = &capsule[32..64];

    let mut pub_blob = Vec::with_capacity(64);
    write_ssh_str(&mut pub_blob, b"ssh-ed25519");
    write_ssh_str(&mut pub_blob, pub_part);

    let check_int: u32 = u32::from_le_bytes([capsule[0], capsule[1], capsule[2], capsule[3]]);
    let mut priv_blob = Vec::with_capacity(192);
    priv_blob.extend_from_slice(&check_int.to_be_bytes());
    priv_blob.extend_from_slice(&check_int.to_be_bytes());
    write_ssh_str(&mut priv_blob, b"ssh-ed25519");
    write_ssh_str(&mut priv_blob, pub_part);
    write_ssh_str(&mut priv_blob, capsule);
    write_ssh_str(&mut priv_blob, comment.as_bytes());
    let mut pad: u8 = 1;
    while !priv_blob.len().is_multiple_of(8) {
        priv_blob.push(pad);
        pad = pad.wrapping_add(1);
    }

    let mut raw = Vec::with_capacity(320);
    raw.extend_from_slice(b"openssh-key-v1\0");
    write_ssh_str(&mut raw, b"none");
    write_ssh_str(&mut raw, b"none");
    write_ssh_str(&mut raw, b"");
    raw.extend_from_slice(&1u32.to_be_bytes());
    write_ssh_str(&mut raw, &pub_blob);
    write_ssh_str(&mut raw, &priv_blob);

    let b64 = BASE64_STD.encode(&raw);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            pem.push_str(line);
            pem.push('\n');
        }
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----");
    pem
}

fn extract_openssh_capsule(pem: &str) -> Result<[u8; CAPSULE64_LEN]> {
    let start = pem
        .find("-----BEGIN OPENSSH PRIVATE KEY-----")
        .ok_or_else(|| anyhow!("missing OpenSSH private key header"))?;
    let rest = &pem[start + "-----BEGIN OPENSSH PRIVATE KEY-----".len()..];
    let end = rest
        .find("-----END OPENSSH PRIVATE KEY-----")
        .ok_or_else(|| anyhow!("missing OpenSSH private key footer"))?;
    let compact: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    let raw = BASE64_STD
        .decode(compact)
        .map_err(|e| anyhow!("invalid OpenSSH Base64 body: {e}"))?;

    if !raw.starts_with(b"openssh-key-v1\0") {
        return Err(anyhow!("invalid openssh-key-v1 magic"));
    }
    let mut cursor = b"openssh-key-v1\0".len();
    let _cipher = read_ssh_str(&raw, &mut cursor)?;
    let _kdf = read_ssh_str(&raw, &mut cursor)?;
    let _kdf_opts = read_ssh_str(&raw, &mut cursor)?;
    if cursor + 4 > raw.len() {
        return Err(anyhow!("missing OpenSSH key count"));
    }
    cursor += 4;
    let _pub_section = read_ssh_str(&raw, &mut cursor)?;
    let priv_section = read_ssh_str(&raw, &mut cursor)?;

    let mut pcur = 8; // skip two uint32 checkints
    if pcur > priv_section.len() {
        return Err(anyhow!("truncated OpenSSH private section"));
    }
    let _key_type = read_ssh_str(priv_section, &mut pcur)?;
    let _pub_copy = read_ssh_str(priv_section, &mut pcur)?;
    let priv_key_bytes = read_ssh_str(priv_section, &mut pcur)?;
    if priv_key_bytes.len() != CAPSULE64_LEN {
        return Err(anyhow!(
            "OpenSSH key slot length {} != {}",
            priv_key_bytes.len(),
            CAPSULE64_LEN
        ));
    }
    let mut out = [0u8; CAPSULE64_LEN];
    out.copy_from_slice(priv_key_bytes);
    Ok(out)
}

/// Mint a honeytoken using ONLY `TaggantPubKey` (zero decryption privilege required).
pub fn mint_canary<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_key: &PublicKey,
    profile: BaitProfile,
    host: &str,
    path: &str,
    branch: &str,
    epoch_minutes: u32,
) -> Result<MintedToken> {
    let ctx = ProvenanceContext {
        profile_id: profile.id().to_string(),
        kind_code: profile.kind_code(),
        epoch_minutes,
        host: host.to_string(),
        path: path.to_string(),
        branch: branch.to_string(),
    };
    let (ht, pt, bt) = ctx.compute_tags();

    let (primary_secret, secondary_secret, host_tag_hex, path_tag_hex, branch_tag_hex) =
        match profile {
            BaitProfile::OpenaiProj => {
                let cap = seal_capsule_64(rng, pub_key, &ctx)?;
                let b62 = encode_base62_fixed(&cap, 86)?;
                (
                    format!("sk-proj-{b62}"),
                    None,
                    hex::encode(ht),
                    hex::encode(pt),
                    hex::encode(bt),
                )
            }
            BaitProfile::AnthropicApi => {
                let cap = seal_capsule_64(rng, pub_key, &ctx)?;
                let b64 = BASE64_URL.encode(cap);
                (
                    format!("sk-ant-api03-{b64}"),
                    None,
                    hex::encode(ht),
                    hex::encode(pt),
                    hex::encode(bt),
                )
            }
            BaitProfile::GithubPat => {
                let cap = seal_capsule_60(rng, pub_key, &ctx)?;
                let b62 = encode_base62_fixed(&cap, 81)?;
                let (head, tail) = b62.split_at(22);
                (
                    format!("github_pat_{head}_{tail}"),
                    None,
                    hex::encode(&ht[..2]),
                    hex::encode(&pt[..3]),
                    hex::encode(&bt[..2]),
                )
            }
            BaitProfile::OpensshKey => {
                let cap = seal_capsule_64(rng, pub_key, &ctx)?;
                let pem = encode_openssh_ed25519_envelope(&cap, "ssh-ed25519-deploy-key");
                (pem, None, hex::encode(ht), hex::encode(pt), hex::encode(bt))
            }
            BaitProfile::GithubClassic => {
                let mut body = String::with_capacity(30);
                let mut buf = [0u8; 1];
                while body.len() < 30 {
                    rng.fill_bytes(&mut buf);
                    if buf[0] < 248 {
                        body.push(BASE62_ALPHABET[(buf[0] % 62) as usize] as char);
                    }
                }
                let crc = encode_u32_base62_6(ieee_crc32(body.as_bytes()));
                (
                    format!("ghp_{body}{crc}"),
                    None,
                    hex::encode(ht),
                    hex::encode(pt),
                    hex::encode(bt),
                )
            }
            BaitProfile::AwsIamPair => {
                let mut ak_bytes = [0u8; 16];
                rng.fill_bytes(&mut ak_bytes);
                let mut ak = String::from("AKIA");
                for b in ak_bytes {
                    ak.push(BASE32_UPPER[(b as usize) % 32] as char);
                }
                let mut sk_raw = [0u8; 30];
                rng.fill_bytes(&mut sk_raw);
                let sk_b64 = BASE64_STD.encode(sk_raw);
                (
                    ak,
                    Some(sk_b64),
                    hex::encode(ht),
                    hex::encode(pt),
                    hex::encode(bt),
                )
            }
        };

    Ok(MintedToken {
        profile,
        env_var: profile.default_env_var().to_string(),
        primary_secret,
        secondary_secret,
        host_tag_hex,
        path_tag_hex,
        branch_tag_hex,
        epoch_minutes,
    })
}

fn decode_to_hit(
    profile: BaitProfile,
    preview: String,
    prov: DecodedProvenance,
) -> Result<StatelessAutopsyHit> {
    let expected = BaitProfile::from_kind_code(prov.kind_code)
        .ok_or_else(|| anyhow!("unknown provenance kind_code {}", prov.kind_code))?;
    if expected != profile {
        return Err(anyhow!(
            "profile mismatch inside capsule: expected {}, got {}",
            profile.id(),
            expected.id()
        ));
    }
    Ok(StatelessAutopsyHit {
        profile,
        token_preview: preview,
        epoch_minutes: prov.epoch_minutes,
        host_tag_hex: prov.host_tag_hex,
        path_tag_hex: prov.path_tag_hex,
        branch_tag_hex: prov.branch_tag_hex,
        compact_mode: prov.compact_mode,
    })
}

/// Perform strictly offline, zero-database `Elligator2` capsule autopsy over any raw token
/// or multi-line blob (logs, `.env`, JSON, or OpenSSH PEM).
pub fn stateless_autopsy_scan(
    input: &str,
    autopsy_sk: &StaticSecret,
) -> Result<Vec<StatelessAutopsyHit>> {
    let mut hits = Vec::new();

    let re_openai = Regex::new(r"sk-proj-([0-9A-Za-z]{86})\b")?;
    for cap in re_openai.captures_iter(input) {
        let full = &cap[0];
        let body = &cap[1];
        if let Ok(raw) = decode_base62_fixed(body, CAPSULE64_LEN)
            && let Ok(arr) = <[u8; CAPSULE64_LEN]>::try_from(raw)
            && let Ok(prov) = open_capsule_64(autopsy_sk, BaitProfile::OpenaiProj.id(), &arr)
        {
            hits.push(decode_to_hit(
                BaitProfile::OpenaiProj,
                abbreviate_token(full),
                prov,
            )?);
        }
    }

    let re_anthropic = Regex::new(r"sk-ant-api03-([A-Za-z0-9_-]{86})\b")?;
    for cap in re_anthropic.captures_iter(input) {
        let full = &cap[0];
        let body = &cap[1];
        if let Ok(raw) = BASE64_URL.decode(body)
            && let Ok(arr) = <[u8; CAPSULE64_LEN]>::try_from(raw)
            && let Ok(prov) = open_capsule_64(autopsy_sk, BaitProfile::AnthropicApi.id(), &arr)
        {
            hits.push(decode_to_hit(
                BaitProfile::AnthropicApi,
                abbreviate_token(full),
                prov,
            )?);
        }
    }

    let re_gh_pat = Regex::new(r"github_pat_([0-9A-Za-z]{22})_([0-9A-Za-z]{59})\b")?;
    for cap in re_gh_pat.captures_iter(input) {
        let full = &cap[0];
        let joined = format!("{}{}", &cap[1], &cap[2]);
        if let Ok(raw) = decode_base62_fixed(&joined, CAPSULE60_LEN)
            && let Ok(arr) = <[u8; CAPSULE60_LEN]>::try_from(raw)
            && let Ok(prov) = open_capsule_60(autopsy_sk, BaitProfile::GithubPat.id(), &arr)
        {
            hits.push(decode_to_hit(
                BaitProfile::GithubPat,
                abbreviate_token(full),
                prov,
            )?);
        }
    }

    let mut search_from = 0;
    while let Some(rel_start) = input[search_from..].find("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let start = search_from + rel_start;
        if let Some(rel_end) = input[start..].find("-----END OPENSSH PRIVATE KEY-----") {
            let end = start + rel_end + "-----END OPENSSH PRIVATE KEY-----".len();
            let pem = &input[start..end];
            if let Ok(arr) = extract_openssh_capsule(pem)
                && let Ok(prov) = open_capsule_64(autopsy_sk, BaitProfile::OpensshKey.id(), &arr)
            {
                hits.push(decode_to_hit(
                    BaitProfile::OpensshKey,
                    "-----BEGIN OPENSSH PRIVATE KEY----- [PEM]".to_string(),
                    prov,
                )?);
            }
            search_from = end;
        } else {
            break;
        }
    }

    Ok(hits)
}

/// Extract all credential-shaped candidates (Tier-1 and Tier-2) from text for fleet verification.
pub fn extract_credential_candidates(input: &str) -> Result<Vec<(String, String)>> {
    let patterns = [
        ("openai-proj", r"sk-proj-[0-9A-Za-z]{86}\b"),
        ("anthropic-api", r"sk-ant-api03-[A-Za-z0-9_-]{86}\b"),
        (
            "github-pat",
            r"github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}\b",
        ),
        ("github-classic", r"ghp_[0-9A-Za-z]{36}\b"),
        ("aws-iam-access", r"\bAKIA[A-Z2-7]{16}\b"),
    ];
    let mut out = Vec::new();
    for (kind, pat) in patterns {
        let re = Regex::new(pat)?;
        for m in re.find_iter(input) {
            out.push((kind.to_string(), m.as_str().to_string()));
        }
    }
    let mut search_from = 0;
    while let Some(rel_start) = input[search_from..].find("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let start = search_from + rel_start;
        if let Some(rel_end) = input[start..].find("-----END OPENSSH PRIVATE KEY-----") {
            let end = start + rel_end + "-----END OPENSSH PRIVATE KEY-----".len();
            out.push(("openssh-key".to_string(), input[start..end].to_string()));
            search_from = end;
        } else {
            break;
        }
    }
    Ok(out)
}

pub fn abbreviate_token(token: &str) -> String {
    if token.len() <= 24 {
        return token.to_string();
    }
    format!("{}...{}", &token[..16], &token[token.len() - 6..])
}
