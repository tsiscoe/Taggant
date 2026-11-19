//! Honeytoken planting and `.env` decoy seeding (`taggant seed`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::formats::{BaitProfile, MintedToken, abbreviate_token, mint_canary};
use crate::vault::{CanaryRecord, TaggantVault};

/// Summary returned by [`seed_target`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedReport {
    pub output_file: PathBuf,
    pub host: String,
    pub branch: String,
    pub epoch_minutes: u32,
    pub minted_count: usize,
    pub recorded_in_vault: bool,
    pub tripwire_url: Option<String>,
}

/// Resolve the local hostname without external network calls.
pub fn resolve_default_host() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "workstation.example.com".to_string()
}

/// Detect the active Git branch near `target`, falling back to `"main"`.
pub fn resolve_git_branch(target: &Path) -> String {
    let probe_dir = if target.is_dir() {
        target
    } else {
        target.parent().unwrap_or(Path::new("."))
    };
    if let Ok(out) = std::process::Command::new("git")
        .arg("-C")
        .arg(probe_dir)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        && out.status.success()
    {
        let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !branch.is_empty() && branch != "HEAD" {
            return branch;
        }
    }
    "main".to_string()
}

pub fn current_epoch_minutes() -> u32 {
    let secs = Utc::now().timestamp().max(0) as u64;
    (secs / 60).min(u32::MAX as u64) as u32
}

/// Record a newly minted decoy into an open `TaggantVault`.
pub fn record_minted_in_vault(
    vault: &mut TaggantVault,
    minted: &MintedToken,
    host: &str,
    target_path: &str,
    branch: &str,
) -> Result<()> {
    let rec = CanaryRecord {
        profile: minted.profile.id().to_string(),
        env_var: minted.env_var.clone(),
        host: host.to_string(),
        target_path: target_path.to_string(),
        branch: branch.to_string(),
        epoch_minutes: minted.epoch_minutes,
        host_tag_hex: minted.host_tag_hex.clone(),
        path_tag_hex: minted.path_tag_hex.clone(),
        branch_tag_hex: minted.branch_tag_hex.clone(),
        token_preview: abbreviate_token(&minted.primary_secret),
        created_at: Utc::now().to_rfc3339(),
    };
    vault.record_canary(&rec, &minted.primary_secret)
}

/// Plant realistic decoy credentials into `target` (writes `.env.staging` if `target` is a directory).
///
/// Requires ONLY `pub_key` on the workstation; optionally logs records when `vault` is supplied.
pub fn seed_target(
    target: &Path,
    pub_key: &PublicKey,
    mut vault: Option<&mut TaggantVault>,
    host: &str,
    branch: &str,
    tripwire_port: Option<u16>,
) -> Result<SeedReport> {
    let output_file = if target.is_dir() || target.to_string_lossy().ends_with(['/', '\\']) {
        std::fs::create_dir_all(target)
            .with_context(|| format!("failed to create directory {}", target.display()))?;
        target.join(".env.staging")
    } else {
        if let Some(parent) = target.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        target.to_path_buf()
    };

    let target_label = output_file.to_string_lossy().to_string();
    let epoch = current_epoch_minutes();
    let mut rng = OsRng;

    let profiles = [
        BaitProfile::OpenaiProj,
        BaitProfile::AnthropicApi,
        BaitProfile::GithubPat,
        BaitProfile::GithubClassic,
        BaitProfile::AwsIamPair,
    ];

    let mut lines = vec![
        "# Staging environment configuration".to_string(),
        format!("# Provisioned UTC: {}", Utc::now().to_rfc3339()),
    ];
    let mut minted_count = 0usize;

    for profile in profiles {
        let minted = mint_canary(
            &mut rng,
            pub_key,
            profile,
            host,
            &target_label,
            branch,
            epoch,
        )?;
        lines.push(format!("{}={}", minted.env_var, minted.primary_secret));
        if let Some(sec) = &minted.secondary_secret {
            lines.push(format!("AWS_SECRET_ACCESS_KEY={sec}"));
        }
        if let Some(v) = vault.as_deref_mut() {
            record_minted_in_vault(v, &minted, host, &target_label, branch)?;
        }
        minted_count += 1;
    }

    let tripwire_url = if let Some(port) = tripwire_port {
        let bait = mint_canary(
            &mut rng,
            pub_key,
            BaitProfile::OpenaiProj,
            host,
            &target_label,
            branch,
            epoch,
        )?;
        if let Some(v) = vault.as_deref_mut() {
            record_minted_in_vault(v, &bait, host, &target_label, branch)?;
        }
        minted_count += 1;
        let url = format!("http://127.0.0.1:{port}/v1/ping/{}", bait.primary_secret);
        lines.push(format!("INTERNAL_TELEMETRY_PING_URL={url}"));
        Some(url)
    } else {
        None
    };

    let content = format!("{}\n", lines.join("\n"));
    std::fs::write(&output_file, content)
        .with_context(|| format!("failed to write decoy env file {}", output_file.display()))?;

    Ok(SeedReport {
        output_file,
        host: host.to_string(),
        branch: branch.to_string(),
        epoch_minutes: epoch,
        minted_count,
        recorded_in_vault: vault.is_some(),
        tripwire_url,
    })
}
