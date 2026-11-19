//! Encrypted SQLite WAL Custody Vault, Context Tag Dictionary, and `BLAKE3` Merkle
//! Tripwire Alert Ledger (`taggant.db`) (`#![forbid(unsafe_code)]`).
//!
//! Security Invariants:
//! - **`TaggantAutopsyKey` Encryption at Rest:** `StaticSecret` bytes are wrapped with
//!   `Argon2id` -> `HKDF-SHA256` -> `XChaCha20-Poly1305` (`taggant-v1|autopsy-secret-key`).
//! - **Encrypted Metadata & Tag Dictionary:** Canary placement metadata (`host`, `target_path`,
//!   `branch`) is authenticated with per-record UUID AAD so `taggant.db` contains zero plaintext
//!   paths or token values.
//! - **Append-Only `BLAKE3` Merkle Alert Chain:** Every loopback tripwire hit chains
//!   `entry_hash = BLAKE3(prev_hash || canonical_fields)` inside `BEGIN IMMEDIATE` transactions.
//! - **Owner-Only Vault & WAL Sidecar ACLs:** `icacls /inheritance:r` on Windows (`0700`/`0600`
//!   on Unix) across parent dir, `taggant.db`, `-wal`, and `-shm`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::{
    MasterSeed, SALT_LEN, TaggantKeypair, VaultSubkeys, aead_decrypt, aead_encrypt,
    blake3_hash_hex, constant_time_eq_32, generate_salt, keyed_blake3_hex,
};

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const AUTOPSY_SK_AAD: &[u8] = b"taggant-v1|autopsy-secret-key";

/// Encrypted metadata record stored for a minted or planted honeytoken.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryRecord {
    pub profile: String,
    pub env_var: String,
    pub host: String,
    pub target_path: String,
    pub branch: String,
    pub epoch_minutes: u32,
    pub host_tag_hex: String,
    pub path_tag_hex: String,
    pub branch_tag_hex: String,
    pub token_preview: String,
    pub created_at: String,
}

/// Optional human-readable tag resolution loaded from `context_tags`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedLabels {
    pub host: Option<String>,
    pub target_path: Option<String>,
    pub branch: Option<String>,
}

/// Input payload to append a loopback tripwire event into the `BLAKE3` Merkle chain.
#[derive(Debug, Clone)]
pub struct NewTripwireAlert {
    pub source_ip: String,
    pub method: String,
    pub request_path: String,
    pub profile: String,
    pub token_preview: String,
    pub host_label: String,
    pub target_path_label: String,
    pub branch_label: String,
}

/// Stored `BLAKE3`-chained loopback tripwire alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripwireAlert {
    pub seq: i64,
    pub timestamp: String,
    pub source_ip: String,
    pub method: String,
    pub request_path: String,
    pub profile: String,
    pub token_preview: String,
    pub host_label: String,
    pub target_path_label: String,
    pub branch_label: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Integrity verification summary returned by [`TaggantVault::verify_alert_chain`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertChainReport {
    pub total_alerts: usize,
    pub head_hash: String,
    pub valid: bool,
}

/// SQLite WAL store managing `TaggantAutopsyKey`, encrypted canary metadata, and Merkle alerts.
pub struct TaggantVault {
    conn: Connection,
    db_path: PathBuf,
    subkeys: VaultSubkeys,
    keypair: TaggantKeypair,
}

impl TaggantVault {
    /// Open or initialize a `TaggantVault` at `db_path` using `passphrase`.
    pub fn open_with_passphrase(db_path: &Path, passphrase: &[u8], fast_kdf: bool) -> Result<Self> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create Taggant vault directory {}",
                    parent.display()
                )
            })?;
            if !fast_kdf {
                enforce_owner_only_acl(parent, true)?;
            }
        }

        let conn = Connection::open(db_path).with_context(|| {
            format!(
                "failed to open Taggant SQLite vault at {}",
                db_path.display()
            )
        })?;

        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;

        Self::init_schema(&conn)?;

        let existing_meta = Self::load_meta(&conn)?;
        let (subkeys, keypair) = match existing_meta {
            Some(meta) => {
                let seed = if fast_kdf {
                    MasterSeed::derive_fast_for_test(passphrase, &meta.salt)?
                } else {
                    MasterSeed::derive_from_passphrase(passphrase, &meta.salt)?
                };
                let sk = seed.derive_subkeys(&meta.salt)?;
                if !constant_time_eq_32(&sk.verifier, &meta.verifier) {
                    return Err(anyhow!(
                        "Invalid master passphrase for Taggant vault at {}",
                        db_path.display()
                    ));
                }
                let mut raw_sk = aead_decrypt(&sk.vault_key, AUTOPSY_SK_AAD, &meta.enc_autopsy_sk)?;
                let sk_arr: [u8; 32] = raw_sk
                    .clone()
                    .try_into()
                    .map_err(|_| anyhow!("corrupt TaggantAutopsyKey length in vault"))?;
                raw_sk.zeroize();

                let kp = TaggantKeypair::from_secret_bytes(sk_arr);
                if kp.pub_key.as_bytes() != meta.pub_key.as_slice() {
                    return Err(anyhow!(
                        "corrupt vault keypair: public key mismatch against decrypted secret"
                    ));
                }
                (sk, kp)
            }
            None => {
                let salt = generate_salt();
                let seed = if fast_kdf {
                    MasterSeed::derive_fast_for_test(passphrase, &salt)?
                } else {
                    MasterSeed::derive_from_passphrase(passphrase, &salt)?
                };
                let sk = seed.derive_subkeys(&salt)?;
                let kp = TaggantKeypair::generate();
                let mut sk_bytes = kp.autopsy_sk.to_bytes();
                let enc_sk = aead_encrypt(&sk.vault_key, AUTOPSY_SK_AAD, &sk_bytes)?;
                sk_bytes.zeroize();

                Self::save_meta(&conn, &salt, &sk.verifier, kp.pub_key.as_bytes(), &enc_sk)?;
                (sk, kp)
            }
        };

        if !fast_kdf {
            enforce_vault_and_sidecar_acls(db_path)?;
        }

        Ok(Self {
            conn,
            db_path: db_path.to_path_buf(),
            subkeys,
            keypair,
        })
    }

    /// Open an in-memory `TaggantVault` for isolated unit and integration tests.
    pub fn open_in_memory_for_test(passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        let salt = [0x42u8; SALT_LEN];
        let seed = MasterSeed::derive_fast_for_test(passphrase, &salt)?;
        let subkeys = seed.derive_subkeys(&salt)?;
        let kp = TaggantKeypair::generate();
        let mut sk_bytes = kp.autopsy_sk.to_bytes();
        let enc_sk = aead_encrypt(&subkeys.vault_key, AUTOPSY_SK_AAD, &sk_bytes)?;
        sk_bytes.zeroize();
        Self::save_meta(
            &conn,
            &salt,
            &subkeys.verifier,
            kp.pub_key.as_bytes(),
            &enc_sk,
        )?;
        Ok(Self {
            conn,
            db_path: PathBuf::from(":memory:"),
            subkeys,
            keypair: kp,
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                pub_key BLOB NOT NULL,
                enc_autopsy_sk BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS canaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_index TEXT UNIQUE NOT NULL,
                profile TEXT NOT NULL,
                created_at TEXT NOT NULL,
                aad_id TEXT NOT NULL,
                ciphertext BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS context_tags (
                tag_index TEXT PRIMARY KEY,
                tag_kind TEXT NOT NULL,
                ciphertext BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tripwire_alerts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                profile TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                ciphertext BLOB NOT NULL
            );",
        )?;
        Ok(())
    }

    fn load_meta(conn: &Connection) -> Result<Option<VaultMetaRow>> {
        let row = conn
            .query_row(
                "SELECT salt, verifier, pub_key, enc_autopsy_sk FROM vault_meta WHERE id = 1",
                [],
                |r| {
                    Ok(RawVaultMetaRow {
                        salt: r.get(0)?,
                        verifier: r.get(1)?,
                        pub_key: r.get(2)?,
                        enc_autopsy_sk: r.get(3)?,
                    })
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(raw) => {
                let salt: [u8; SALT_LEN] = raw
                    .salt
                    .try_into()
                    .map_err(|_| anyhow!("corrupt vault salt length"))?;
                let verifier: [u8; 32] = raw
                    .verifier
                    .try_into()
                    .map_err(|_| anyhow!("corrupt vault verifier length"))?;
                Ok(Some(VaultMetaRow {
                    salt,
                    verifier,
                    pub_key: raw.pub_key,
                    enc_autopsy_sk: raw.enc_autopsy_sk,
                }))
            }
        }
    }

    fn save_meta(
        conn: &Connection,
        salt: &[u8; SALT_LEN],
        verifier: &[u8; 32],
        pub_key: &[u8],
        enc_autopsy_sk: &[u8],
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO vault_meta (id, salt, verifier, pub_key, enc_autopsy_sk) VALUES (1, ?1, ?2, ?3, ?4)",
            params![salt.as_slice(), verifier.as_slice(), pub_key, enc_autopsy_sk],
        )?;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.pub_key
    }

    pub fn public_key_b64(&self) -> String {
        format!(
            "taggant-pub-v1:{}",
            BASE64_STD.encode(self.keypair.pub_key.as_bytes())
        )
    }

    pub fn autopsy_secret(&self) -> &StaticSecret {
        &self.keypair.autopsy_sk
    }

    /// Record a canary's encrypted metadata and index both full and compact `BLAKE3` context tags
    /// inside an atomic `BEGIN IMMEDIATE` transaction.
    pub fn record_canary(&mut self, record: &CanaryRecord, primary_secret: &str) -> Result<()> {
        let token_index = keyed_blake3_hex(
            &self.subkeys.mac_key,
            "taggant-v1-token",
            primary_secret.as_bytes(),
        );
        let aad_id = Uuid::new_v4().to_string();
        let aad = format!("taggant-v1|canary|{aad_id}");
        let plaintext = serde_json::to_vec(record)?;
        let ciphertext = aead_encrypt(&self.subkeys.vault_key, aad.as_bytes(), &plaintext)?;

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;

        tx.execute(
            "INSERT INTO canaries (token_index, profile, created_at, aad_id, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(token_index) DO UPDATE SET
               profile = excluded.profile,
               created_at = excluded.created_at,
               aad_id = excluded.aad_id,
               ciphertext = excluded.ciphertext",
            params![
                token_index,
                record.profile,
                record.created_at,
                aad_id,
                ciphertext
            ],
        )?;

        // Index both 64B tag widths (3B/4B/4B) and 60B compact tag widths (2B/3B/2B)
        let h_hash = blake3::hash(record.host.as_bytes());
        let p_hash = blake3::hash(record.target_path.as_bytes());
        let b_hash = blake3::hash(record.branch.as_bytes());

        let tag_entries = [
            ("host", hex::encode(&h_hash.as_bytes()[..3]), &record.host),
            ("host", hex::encode(&h_hash.as_bytes()[..2]), &record.host),
            (
                "path",
                hex::encode(&p_hash.as_bytes()[..4]),
                &record.target_path,
            ),
            (
                "path",
                hex::encode(&p_hash.as_bytes()[..3]),
                &record.target_path,
            ),
            (
                "branch",
                hex::encode(&b_hash.as_bytes()[..4]),
                &record.branch,
            ),
            (
                "branch",
                hex::encode(&b_hash.as_bytes()[..2]),
                &record.branch,
            ),
        ];

        for (kind, tag_hex, value) in tag_entries {
            let key_input = format!("{kind}:{tag_hex}");
            let tag_index = keyed_blake3_hex(
                &self.subkeys.mac_key,
                "taggant-v1-tag",
                key_input.as_bytes(),
            );
            let ctx_aad = format!("taggant-v1|ctx|{tag_index}");
            let ct = aead_encrypt(
                &self.subkeys.vault_key,
                ctx_aad.as_bytes(),
                value.as_bytes(),
            )?;
            tx.execute(
                "INSERT INTO context_tags (tag_index, tag_kind, ciphertext)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(tag_index) DO UPDATE SET ciphertext = excluded.ciphertext",
                params![tag_index, kind, ct],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Look up a token by keyed `BLAKE3` blind index (used for Tier-2 tokens and fleet checks).
    pub fn lookup_canary_by_secret(&self, primary_secret: &str) -> Result<Option<CanaryRecord>> {
        let token_index = keyed_blake3_hex(
            &self.subkeys.mac_key,
            "taggant-v1-token",
            primary_secret.as_bytes(),
        );
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT aad_id, ciphertext FROM canaries WHERE token_index = ?1",
                params![token_index],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((aad_id, ct)) => {
                let aad = format!("taggant-v1|canary|{aad_id}");
                let pt = aead_decrypt(&self.subkeys.vault_key, aad.as_bytes(), &ct)?;
                let rec: CanaryRecord = serde_json::from_slice(&pt)?;
                Ok(Some(rec))
            }
        }
    }

    /// List all planted canaries stored in the encrypted vault.
    pub fn list_canaries(&self) -> Result<Vec<CanaryRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT aad_id, ciphertext FROM canaries ORDER BY id DESC")?;
        let rows = stmt.query_map([], |r| {
            let aad_id: String = r.get(0)?;
            let ct: Vec<u8> = r.get(1)?;
            Ok((aad_id, ct))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (aad_id, ct) = row?;
            let aad = format!("taggant-v1|canary|{aad_id}");
            let pt = aead_decrypt(&self.subkeys.vault_key, aad.as_bytes(), &ct)?;
            let rec: CanaryRecord = serde_json::from_slice(&pt)?;
            out.push(rec);
        }
        Ok(out)
    }

    fn resolve_single_tag(&self, kind: &str, tag_hex: &str) -> Result<Option<String>> {
        let key_input = format!("{kind}:{tag_hex}");
        let tag_index = keyed_blake3_hex(
            &self.subkeys.mac_key,
            "taggant-v1-tag",
            key_input.as_bytes(),
        );
        let ct: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT ciphertext FROM context_tags WHERE tag_index = ?1",
                params![tag_index],
                |r| r.get(0),
            )
            .optional()?;
        match ct {
            None => Ok(None),
            Some(blob) => {
                let ctx_aad = format!("taggant-v1|ctx|{tag_index}");
                let pt = aead_decrypt(&self.subkeys.vault_key, ctx_aad.as_bytes(), &blob)?;
                Ok(Some(String::from_utf8(pt)?))
            }
        }
    }

    /// Resolve short `BLAKE3` provenance tags to full human-readable labels if present in `taggant.db`.
    pub fn resolve_context_labels(
        &self,
        host_tag_hex: &str,
        path_tag_hex: &str,
        branch_tag_hex: &str,
    ) -> Result<ResolvedLabels> {
        Ok(ResolvedLabels {
            host: self.resolve_single_tag("host", host_tag_hex)?,
            target_path: self.resolve_single_tag("path", path_tag_hex)?,
            branch: self.resolve_single_tag("branch", branch_tag_hex)?,
        })
    }

    /// Append a loopback tripwire hit into the `BLAKE3` Merkle hash-chain atomically with
    /// encrypted alert body (`XChaCha20-Poly1305`).
    pub fn append_tripwire_alert(&mut self, alert: NewTripwireAlert) -> Result<TripwireAlert> {
        let timestamp = Utc::now().to_rfc3339();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;

        let prev_hash: String = tx
            .query_row(
                "SELECT entry_hash FROM tripwire_alerts ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());

        let entry_hash = compute_alert_entry_hash(
            &prev_hash,
            &timestamp,
            &alert.source_ip,
            &alert.method,
            &alert.request_path,
            &alert.profile,
            &alert.token_preview,
            &alert.host_label,
            &alert.target_path_label,
            &alert.branch_label,
        );

        let body = EncryptedAlertBody {
            source_ip: alert.source_ip.clone(),
            method: alert.method.clone(),
            request_path: alert.request_path.clone(),
            token_preview: alert.token_preview.clone(),
            host_label: alert.host_label.clone(),
            target_path_label: alert.target_path_label.clone(),
            branch_label: alert.branch_label.clone(),
        };
        let aad = format!("taggant-v1|alert|{prev_hash}|{timestamp}|{}", alert.profile);
        let ciphertext = aead_encrypt(
            &self.subkeys.vault_key,
            aad.as_bytes(),
            &serde_json::to_vec(&body)?,
        )?;

        tx.execute(
            "INSERT INTO tripwire_alerts (
                timestamp, profile, prev_hash, entry_hash, ciphertext
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![timestamp, alert.profile, prev_hash, entry_hash, ciphertext,],
        )?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;

        Ok(TripwireAlert {
            seq,
            timestamp,
            source_ip: alert.source_ip,
            method: alert.method,
            request_path: alert.request_path,
            profile: alert.profile,
            token_preview: alert.token_preview,
            host_label: alert.host_label,
            target_path_label: alert.target_path_label,
            branch_label: alert.branch_label,
            prev_hash,
            entry_hash,
        })
    }

    fn decrypt_alert_row(
        &self,
        seq: i64,
        timestamp: String,
        profile: String,
        prev_hash: String,
        entry_hash: String,
        ciphertext: Vec<u8>,
    ) -> Result<TripwireAlert> {
        let aad = format!("taggant-v1|alert|{prev_hash}|{timestamp}|{profile}");
        let pt = aead_decrypt(&self.subkeys.vault_key, aad.as_bytes(), &ciphertext)?;
        let body: EncryptedAlertBody = serde_json::from_slice(&pt)?;
        Ok(TripwireAlert {
            seq,
            timestamp,
            source_ip: body.source_ip,
            method: body.method,
            request_path: body.request_path,
            profile,
            token_preview: body.token_preview,
            host_label: body.host_label,
            target_path_label: body.target_path_label,
            branch_label: body.branch_label,
            prev_hash,
            entry_hash,
        })
    }

    /// Retrieve recent tripwire alerts newest-first.
    pub fn list_tripwire_alerts(&self, limit: usize) -> Result<Vec<TripwireAlert>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, timestamp, profile, prev_hash, entry_hash, ciphertext
             FROM tripwire_alerts ORDER BY seq DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, ts, prof, prev, hash, ct) = row?;
            out.push(self.decrypt_alert_row(seq, ts, prof, prev, hash, ct)?);
        }
        Ok(out)
    }

    /// Verify the entire `tripwire_alerts` `BLAKE3` Merkle hash-chain from genesis to head.
    pub fn verify_alert_chain(&self) -> Result<AlertChainReport> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, timestamp, profile, prev_hash, entry_hash, ciphertext
             FROM tripwire_alerts ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;

        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        let mut count = 0usize;
        for row in rows {
            let (seq, ts, prof, prev, hash, ct) = row?;
            let entry = self.decrypt_alert_row(seq, ts, prof, prev, hash, ct)?;
            if entry.prev_hash != expected_prev {
                return Err(anyhow!(
                    "Merkle chain break at seq {}: expected prev_hash {}, found {}",
                    entry.seq,
                    expected_prev,
                    entry.prev_hash
                ));
            }
            let recomputed = compute_alert_entry_hash(
                &entry.prev_hash,
                &entry.timestamp,
                &entry.source_ip,
                &entry.method,
                &entry.request_path,
                &entry.profile,
                &entry.token_preview,
                &entry.host_label,
                &entry.target_path_label,
                &entry.branch_label,
            );
            if entry.entry_hash != recomputed {
                return Err(anyhow!(
                    "Merkle entry hash mismatch at seq {}: expected {}, found {}",
                    entry.seq,
                    recomputed,
                    entry.entry_hash
                ));
            }
            expected_prev = entry.entry_hash;
            count += 1;
        }

        Ok(AlertChainReport {
            total_alerts: count,
            head_hash: expected_prev,
            valid: true,
        })
    }
}

struct RawVaultMetaRow {
    salt: Vec<u8>,
    verifier: Vec<u8>,
    pub_key: Vec<u8>,
    enc_autopsy_sk: Vec<u8>,
}

struct VaultMetaRow {
    salt: [u8; SALT_LEN],
    verifier: [u8; 32],
    pub_key: Vec<u8>,
    enc_autopsy_sk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedAlertBody {
    source_ip: String,
    method: String,
    request_path: String,
    token_preview: String,
    host_label: String,
    target_path_label: String,
    branch_label: String,
}

#[allow(clippy::too_many_arguments)]
fn compute_alert_entry_hash(
    prev_hash: &str,
    timestamp: &str,
    source_ip: &str,
    method: &str,
    request_path: &str,
    profile: &str,
    token_preview: &str,
    host_label: &str,
    target_path_label: &str,
    branch_label: &str,
) -> String {
    let payload = serde_json::json!([
        "taggant-alert-v1",
        prev_hash,
        timestamp,
        source_ip,
        method,
        request_path,
        profile,
        token_preview,
        host_label,
        target_path_label,
        branch_label,
    ])
    .to_string();
    blake3_hash_hex(&[prev_hash.as_bytes(), b"|", payload.as_bytes()])
}

/// Enforce owner-only ACLs on the vault directory, `taggant.db`, `-wal`, and `-shm` sidecars (`CWE-732`).
pub fn enforce_vault_and_sidecar_acls(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
        && parent.exists()
    {
        enforce_owner_only_acl(parent, true)?;
    }
    if db_path.exists() {
        enforce_owner_only_acl(db_path, false)?;
    }
    let db_os = db_path.as_os_str();
    for suffix in ["-wal", "-shm"] {
        let mut sidecar_os = db_os.to_os_string();
        sidecar_os.push(suffix);
        let sidecar_path = PathBuf::from(sidecar_os);
        if sidecar_path.exists() {
            enforce_owner_only_acl(&sidecar_path, false)?;
        }
    }
    Ok(())
}

/// Enforce strict owner-only filesystem ACLs (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix).
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set mode {:o} on {}", mode, path.display()))?;
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(anyhow!(
                "effective Unix mode {:o} != expected {:o} on {}",
                applied,
                mode,
                path.display()
            ));
        }
    }

    #[cfg(windows)]
    {
        let principal = resolve_windows_owner_principal()?;
        let grant_spec = if is_dir {
            format!("{principal}:(OI)(CI)F")
        } else {
            format!("{principal}:F")
        };
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant_spec)
            .output()
            .with_context(|| format!("failed to execute icacls on {}", path.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "icacls failed to enforce owner-only ACL on {} (status={}): {} {}",
                path.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn resolve_windows_owner_principal() -> Result<String> {
    if let Ok(out) = std::process::Command::new("whoami").output()
        && out.status.success()
    {
        let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !who.is_empty() {
            return Ok(who);
        }
    }
    if let Ok(username) = std::env::var("USERNAME") {
        let trimmed = username.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(anyhow!(
        "Unable to resolve Windows owner principal via `whoami` or `USERNAME`"
    ))
}
