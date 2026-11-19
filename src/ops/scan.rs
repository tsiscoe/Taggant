//! Offline autopsy scanner and `/loom` fleet sterility gate (`taggant autopsy`, `taggant verify-fleet`).

use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

use crate::formats::{
    abbreviate_token, extract_credential_candidates, stateless_autopsy_scan,
    verify_github_classic_crc,
};
use crate::vault::TaggantVault;

/// Unified forensic autopsy finding across Tier-1 (stateless) and Tier-2 (vault-indexed) tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnifiedAutopsyResult {
    pub tier: String,
    pub profile: String,
    pub token_preview: String,
    pub epoch_minutes: Option<u32>,
    pub minted_utc: Option<String>,
    pub host_tag_hex: String,
    pub path_tag_hex: String,
    pub branch_tag_hex: String,
    pub resolved_host: Option<String>,
    pub resolved_path: Option<String>,
    pub resolved_branch: Option<String>,
}

/// Classification outcome for a credential-shaped token found during `verify-fleet`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetMatch {
    pub file: PathBuf,
    pub kind: String,
    pub token_preview: String,
    pub status: String,
    pub verified_canary: bool,
}

/// Repository hygiene report distinguishing verified Taggant decoys from unregistered leaks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetScanReport {
    pub root: PathBuf,
    pub scanned_files: usize,
    pub verified_canaries: Vec<FleetMatch>,
    pub unregistered_secrets: Vec<FleetMatch>,
}

pub fn format_epoch_minutes_utc(epoch_minutes: u32) -> Option<String> {
    let ts = (epoch_minutes as i64) * 60;
    DateTime::from_timestamp(ts, 0).map(|dt| dt.to_rfc3339())
}

/// Perform offline `Elligator2` capsule autopsy on arbitrary text, optionally enriching short
/// `BLAKE3` provenance tags and Tier-2 indexes via an unlocked `TaggantVault`.
pub fn run_autopsy(
    input: &str,
    autopsy_sk: &StaticSecret,
    vault: Option<&TaggantVault>,
) -> Result<Vec<UnifiedAutopsyResult>> {
    let mut results = Vec::new();
    let tier1_hits = stateless_autopsy_scan(input, autopsy_sk)?;

    for hit in tier1_hits {
        let labels = if let Some(v) = vault {
            v.resolve_context_labels(&hit.host_tag_hex, &hit.path_tag_hex, &hit.branch_tag_hex)?
        } else {
            Default::default()
        };
        results.push(UnifiedAutopsyResult {
            tier: if hit.compact_mode {
                "tier1-stateless-60B".to_string()
            } else {
                "tier1-stateless-64B".to_string()
            },
            profile: hit.profile.id().to_string(),
            token_preview: hit.token_preview,
            epoch_minutes: Some(hit.epoch_minutes),
            minted_utc: format_epoch_minutes_utc(hit.epoch_minutes),
            host_tag_hex: hit.host_tag_hex,
            path_tag_hex: hit.path_tag_hex,
            branch_tag_hex: hit.branch_tag_hex,
            resolved_host: labels.host,
            resolved_path: labels.target_path,
            resolved_branch: labels.branch,
        });
    }

    if let Some(v) = vault {
        for (kind, tok) in extract_credential_candidates(input)? {
            if (kind == "github-classic" || kind == "aws-iam-access")
                && let Some(rec) = v.lookup_canary_by_secret(&tok)?
            {
                results.push(UnifiedAutopsyResult {
                    tier: "tier2-vault-indexed".to_string(),
                    profile: rec.profile,
                    token_preview: abbreviate_token(&tok),
                    epoch_minutes: Some(rec.epoch_minutes),
                    minted_utc: format_epoch_minutes_utc(rec.epoch_minutes),
                    host_tag_hex: rec.host_tag_hex,
                    path_tag_hex: rec.path_tag_hex,
                    branch_tag_hex: rec.branch_tag_hex,
                    resolved_host: Some(rec.host),
                    resolved_path: Some(rec.target_path),
                    resolved_branch: Some(rec.branch),
                });
            }
        }
    }

    Ok(results)
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "dist" | "build"
    )
}

fn collect_text_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if dir.is_file() {
        out.push(dir.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if path.is_dir() {
            if !should_skip_dir(&name) {
                collect_text_files(&path, out)?;
            }
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Walk `root` and classify every credential-shaped string as either `[TAGGANT:CANARY:VERIFIED]`
/// or `[UNREGISTERED_SECRET]`.
pub fn verify_fleet_directory(
    root: &Path,
    autopsy_sk: Option<&StaticSecret>,
    vault: Option<&TaggantVault>,
) -> Result<FleetScanReport> {
    let mut files = Vec::new();
    collect_text_files(root, &mut files)?;

    let mut scanned_files = 0usize;
    let mut verified_canaries = Vec::new();
    let mut unregistered_secrets = Vec::new();

    for file in files {
        let Ok(raw_bytes) = std::fs::read(&file) else {
            continue;
        };
        if raw_bytes.len() > 4 * 1024 * 1024 || raw_bytes.contains(&0u8) {
            continue;
        }
        let Ok(text) = String::from_utf8(raw_bytes) else {
            continue;
        };
        scanned_files += 1;

        let candidates = extract_credential_candidates(&text)?;
        if candidates.is_empty() {
            continue;
        }

        for (kind, tok) in candidates {
            let mut is_verified = false;
            if matches!(
                kind.as_str(),
                "openai-proj" | "anthropic-api" | "github-pat" | "openssh-key"
            ) {
                if let Some(sk) = autopsy_sk
                    && !stateless_autopsy_scan(&tok, sk)?.is_empty()
                {
                    is_verified = true;
                }
            } else if kind == "github-classic" {
                if verify_github_classic_crc(&tok)
                    && let Some(v) = vault
                    && v.lookup_canary_by_secret(&tok)?.is_some()
                {
                    is_verified = true;
                }
            } else if kind == "aws-iam-access"
                && let Some(v) = vault
                && v.lookup_canary_by_secret(&tok)?.is_some()
            {
                is_verified = true;
            }

            let preview = if kind == "openssh-key" {
                "-----BEGIN OPENSSH PRIVATE KEY----- [PEM]".to_string()
            } else {
                abbreviate_token(&tok)
            };

            if is_verified {
                verified_canaries.push(FleetMatch {
                    file: file.clone(),
                    kind,
                    token_preview: preview,
                    status: "[TAGGANT:CANARY:VERIFIED]".to_string(),
                    verified_canary: true,
                });
            } else {
                unregistered_secrets.push(FleetMatch {
                    file: file.clone(),
                    kind,
                    token_preview: preview,
                    status: "[UNREGISTERED_SECRET]".to_string(),
                    verified_canary: false,
                });
            }
        }
    }

    Ok(FleetScanReport {
        root: root.to_path_buf(),
        scanned_files,
        verified_canaries,
        unregistered_secrets,
    })
}
