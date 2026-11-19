#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use rand::rngs::OsRng;
use tokio::sync::watch;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use taggant::cli::{Cli, Commands};
use taggant::crypto::{parse_public_key, parse_secret_key};
use taggant::formats::{BaitProfile, mint_canary};
use taggant::ops::{
    scan::{run_autopsy, verify_fleet_directory},
    seed::{
        current_epoch_minutes, record_minted_in_vault, resolve_default_host, resolve_git_branch,
        seed_target,
    },
    watch::serve_loopback_tripwire,
};
use taggant::tui::{TaggantTuiApp, run_interactive_tui};
use taggant::vault::TaggantVault;

const KEYRING_SERVICE: &str = "taggant-vault";
const KEYRING_USER: &str = "default-passphrase";

fn default_vault_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("taggant")
        .join("taggant.db")
}

fn resolve_passphrase(use_keyring: bool, creating: bool) -> Result<Vec<u8>> {
    if let Ok(env_pw) = std::env::var("TAGGANT_PASSPHRASE")
        && !env_pw.is_empty()
    {
        return Ok(env_pw.into_bytes());
    }

    if use_keyring {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|e| anyhow!("OS keyring entry init failed: {e}"))?;
        if !creating {
            match entry.get_password() {
                Ok(pw) if !pw.is_empty() => return Ok(pw.into_bytes()),
                Ok(_) => {}
                Err(err) => {
                    eprintln!("OS keyring lookup missed ({err}); falling back to prompt.");
                }
            }
        }
    }

    let prompt = if creating {
        "Create Taggant vault passphrase: "
    } else {
        "Taggant vault passphrase: "
    };
    let pw = rpassword::prompt_password(prompt).context("failed to read vault passphrase")?;
    if pw.is_empty() {
        return Err(anyhow!("vault passphrase cannot be empty"));
    }

    if creating {
        let confirm = rpassword::prompt_password("Confirm Taggant vault passphrase: ")
            .context("failed to read confirmation passphrase")?;
        if pw != confirm {
            return Err(anyhow!("passphrases did not match"));
        }
        if use_keyring {
            let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
                .map_err(|e| anyhow!("OS keyring entry init failed: {e}"))?;
            entry
                .set_password(&pw)
                .map_err(|e| anyhow!("failed to store passphrase in OS keyring: {e}"))?;
        }
    }

    Ok(pw.into_bytes())
}

fn open_vault(
    vault_arg: Option<PathBuf>,
    use_keyring: bool,
    must_exist: bool,
) -> Result<TaggantVault> {
    let path = vault_arg.unwrap_or_else(default_vault_path);
    let exists = path.exists();
    if must_exist && !exists {
        return Err(anyhow!(
            "Taggant vault does not exist at {} (run `taggant init` first)",
            path.display()
        ));
    }
    let mut pw = resolve_passphrase(use_keyring, !exists)?;
    let res = TaggantVault::open_with_passphrase(&path, &pw, false);
    pw.zeroize();
    res
}

fn load_public_key_spec(spec: &str) -> Result<PublicKey> {
    let candidate = Path::new(spec);
    if candidate.exists() && candidate.is_file() {
        let contents = std::fs::read_to_string(candidate)
            .with_context(|| format!("failed to read public key file {}", candidate.display()))?;
        return parse_public_key(&contents);
    }
    parse_public_key(spec)
}

fn load_autopsy_input(spec: &str) -> Result<String> {
    if spec == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(buf);
    }
    let p = Path::new(spec);
    if p.exists() && p.is_file() {
        return std::fs::read_to_string(p)
            .with_context(|| format!("failed to read autopsy target file {}", p.display()));
    }
    Ok(spec.to_string())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { export_pub } => {
            let vault = open_vault(cli.vault, cli.keyring, false)?;
            let pub_b64 = vault.public_key_b64();
            if let Some(out_path) = export_pub {
                if let Some(parent) = out_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, format!("{pub_b64}\n"))?;
            }
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "vault": vault.db_path(),
                        "public_key": pub_b64,
                    }))?
                );
            } else {
                println!("Initialized Taggant vault: {}", vault.db_path().display());
                println!("Safe-to-distribute TaggantPubKey: {pub_b64}");
            }
        }

        Commands::Mint {
            profile,
            pub_key,
            host,
            path,
            branch,
            record,
        } => {
            let prof = BaitProfile::from_str_id(&profile)?;
            let host_str = host.unwrap_or_else(resolve_default_host);
            let branch_str = branch.unwrap_or_else(|| resolve_git_branch(Path::new(".")));
            let epoch = current_epoch_minutes();

            let mut maybe_vault = if let Some(pk_spec) = pub_key.as_deref() {
                let _ = load_public_key_spec(pk_spec)?;
                if record {
                    Some(open_vault(cli.vault, cli.keyring, true)?)
                } else {
                    None
                }
            } else {
                Some(open_vault(cli.vault, cli.keyring, true)?)
            };

            let pk = match pub_key.as_deref() {
                Some(spec) => load_public_key_spec(spec)?,
                None => maybe_vault
                    .as_ref()
                    .ok_or_else(|| anyhow!("vault required when --pub-key is omitted"))?
                    .public_key(),
            };

            let mut rng = OsRng;
            let minted = mint_canary(&mut rng, &pk, prof, &host_str, &path, &branch_str, epoch)?;

            if record && let Some(ref mut v) = maybe_vault {
                record_minted_in_vault(v, &minted, &host_str, &path, &branch_str)?;
            }

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&minted)?);
            } else {
                println!("Profile: {}", minted.profile.id());
                println!("{}={}", minted.env_var, minted.primary_secret);
                if let Some(sec) = minted.secondary_secret {
                    println!("AWS_SECRET_ACCESS_KEY={sec}");
                }
            }
        }

        Commands::Seed {
            target,
            pub_key,
            host,
            branch,
            with_tripwire_port,
        } => {
            let host_str = host.unwrap_or_else(resolve_default_host);
            let branch_str = branch.unwrap_or_else(|| resolve_git_branch(&target));

            let (pk, mut vault_opt) = if let Some(pk_spec) = pub_key {
                (load_public_key_spec(&pk_spec)?, None)
            } else {
                let v = open_vault(cli.vault, cli.keyring, true)?;
                (v.public_key(), Some(v))
            };

            let report = seed_target(
                &target,
                &pk,
                vault_opt.as_mut(),
                &host_str,
                &branch_str,
                with_tripwire_port,
            )?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Seeded {} honeytokens into {}",
                    report.minted_count,
                    report.output_file.display()
                );
                if let Some(url) = report.tripwire_url {
                    println!("Loopback Tripwire Bait URL: {url}");
                }
            }
        }

        Commands::Autopsy { input, secret_key } => {
            let text = load_autopsy_input(&input)?;
            let (sk, vault_opt): (StaticSecret, Option<TaggantVault>) = match secret_key {
                Some(sk_spec) => (parse_secret_key(&sk_spec)?, None),
                None => {
                    let v = open_vault(cli.vault, cli.keyring, true)?;
                    let sk = v.autopsy_secret().clone();
                    (sk, Some(v))
                }
            };

            let hits = run_autopsy(&text, &sk, vault_opt.as_ref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&hits)?);
            } else if hits.is_empty() {
                println!("No verified Taggant honeytokens detected in input.");
            } else {
                for (idx, hit) in hits.iter().enumerate() {
                    println!(
                        "[{}] {} ({}) :: {}",
                        idx + 1,
                        hit.profile,
                        hit.tier,
                        hit.token_preview
                    );
                    println!(
                        "    minted={} host={} ({}) path={} ({}) branch={} ({})",
                        hit.minted_utc.as_deref().unwrap_or("unknown"),
                        hit.host_tag_hex,
                        hit.resolved_host.as_deref().unwrap_or("offline-tag-only"),
                        hit.path_tag_hex,
                        hit.resolved_path.as_deref().unwrap_or("offline-tag-only"),
                        hit.branch_tag_hex,
                        hit.resolved_branch.as_deref().unwrap_or("offline-tag-only"),
                    );
                }
            }
        }

        Commands::VerifyFleet {
            dir,
            secret_key,
            fail_on_any,
        } => {
            let (sk_opt, vault_opt) = match secret_key {
                Some(sk_spec) => (Some(parse_secret_key(&sk_spec)?), None),
                None => {
                    let v = open_vault(cli.vault, cli.keyring, true)?;
                    let sk = v.autopsy_secret().clone();
                    (Some(sk), Some(v))
                }
            };

            let report = verify_fleet_directory(&dir, sk_opt.as_ref(), vault_opt.as_ref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Scanned {} files in {} | Verified Canaries: {} | Unregistered Secrets: {}",
                    report.scanned_files,
                    report.root.display(),
                    report.verified_canaries.len(),
                    report.unregistered_secrets.len()
                );
                for m in &report.verified_canaries {
                    println!("  {} {} ({})", m.status, m.file.display(), m.token_preview);
                }
                for m in &report.unregistered_secrets {
                    println!("  {} {} ({})", m.status, m.file.display(), m.token_preview);
                }
            }

            if !report.unregistered_secrets.is_empty()
                || (fail_on_any && !report.verified_canaries.is_empty())
            {
                std::process::exit(1);
            }
        }

        Commands::Watch { bind } => {
            let vault = open_vault(cli.vault, cli.keyring, true)?;
            let shared_vault = Arc::new(Mutex::new(vault));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let (_tx, rx) = watch::channel(false);
            eprintln!("Taggant loopback tripwire listening on http://{bind}");
            rt.block_on(serve_loopback_tripwire(bind, shared_vault, None, rx, true))?;
        }

        Commands::Tui { autopsy_file } => {
            let vault = open_vault(cli.vault, cli.keyring, true)?;
            let canaries = vault.list_canaries()?;
            let alerts = vault.list_tripwire_alerts(200)?;
            let chain_report = vault.verify_alert_chain()?;
            let autopsy_hits = if let Some(path) = autopsy_file {
                let raw = std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read autopsy file {}", path.display()))?;
                run_autopsy(&raw, vault.autopsy_secret(), Some(&vault))?
            } else {
                Vec::new()
            };

            let app = TaggantTuiApp::new(
                vault.db_path().display().to_string(),
                vault.public_key_b64(),
                canaries,
                autopsy_hits,
                alerts,
                chain_report,
            );
            run_interactive_tui(app)?;
        }

        Commands::ExportKey { autopsy_secret } => {
            let vault = open_vault(cli.vault, cli.keyring, true)?;
            if autopsy_secret {
                let mut sk_bytes = vault.autopsy_secret().to_bytes();
                let encoded = format!("taggant-sec-v1:{}", hex::encode(sk_bytes));
                sk_bytes.zeroize();
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "public_key": vault.public_key_b64(),
                            "autopsy_secret_key": encoded,
                        }))?
                    );
                } else {
                    println!("{encoded}");
                }
            } else if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "public_key": vault.public_key_b64(),
                    }))?
                );
            } else {
                println!("{}", vault.public_key_b64());
            }
        }
    }

    Ok(())
}
