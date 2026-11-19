//! Comprehensive cryptographic, protocol, vault, loopback tripwire, and Ratatui TestBackend
//! integration tests for **Taggant** (`taggant v0.1.0`).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use rand::{SeedableRng, rngs::StdRng};
use ratatui::{Terminal, backend::TestBackend};
use rusqlite::Connection;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use x25519_dalek::{PublicKey, StaticSecret};

use taggant::crypto::TaggantKeypair;
use taggant::crypto::capsule::{ProvenanceContext, open_capsule_64, seal_capsule_64};
use taggant::crypto::elligator::{
    elligator2_branch_sign, elligator2_decode, elligator2_generate_ephemeral,
};
use taggant::crypto::fe25519::Fe25519;
use taggant::formats::{
    BaitProfile, decode_base62_fixed, encode_base62_fixed, mint_canary, stateless_autopsy_scan,
    verify_github_classic_crc,
};
use taggant::ops::{
    scan::{run_autopsy, verify_fleet_directory},
    seed::seed_target,
    watch::serve_loopback_tripwire,
};
use taggant::tui::{
    TaggantTuiApp,
    ui::{render, sanitize_terminal_str},
};
use taggant::vault::{
    CanaryRecord, NewTripwireAlert, TaggantVault, enforce_vault_and_sidecar_acls,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_elligator2_roundtrip_and_canonical_bounds(seed_bytes in any::<[u8; 32]>()) {
        let mut rng = StdRng::from_seed(seed_bytes);
        let (sk, repr) = elligator2_generate_ephemeral(&mut rng);
        let pk = PublicKey::from(&sk);
        let decoded_u = elligator2_decode(&repr);
        prop_assert_eq!(decoded_u, *pk.as_bytes());
    }
}

#[test]
fn test_fe25519_arithmetic_and_sqrt_laws() {
    let a = Fe25519::from_u64(486662);
    let b = Fe25519::from_u64(19);
    let inv_b = b.inv();
    assert_eq!(b * inv_b, Fe25519::ONE);

    let diff = a - a;
    assert!(diff.is_zero());

    let sq = Fe25519::from_u64(25).sqrt().expect("25 is a square");
    assert_eq!(sq.square(), Fe25519::from_u64(25));

    // Z = 2 is non-square mod 2^255 - 19
    assert!(Fe25519::TWO.sqrt().is_none());
}

#[test]
fn test_elligator2_branch_and_top_bits_statistical_uniformity() {
    let mut rng = StdRng::seed_from_u64(0xB4A1_0001_CAFE_F00Du64);
    let total = 512usize;
    let mut pos_branch = 0usize;
    let mut neg_branch = 0usize;
    let mut top2_hist = [0usize; 4];

    for _ in 0..total {
        let (sk, repr) = elligator2_generate_ephemeral(&mut rng);
        assert_eq!(elligator2_decode(&repr), *PublicKey::from(&sk).as_bytes());

        match elligator2_branch_sign(&repr) {
            1 => pos_branch += 1,
            -1 => neg_branch += 1,
            other => panic!("unexpected branch sign {other}"),
        }
        let top2 = (repr[31] >> 6) as usize;
        top2_hist[top2] += 1;
    }

    let min_branch = (total * 38) / 100;
    let max_branch = (total * 62) / 100;
    assert!(
        (min_branch..=max_branch).contains(&pos_branch),
        "positive branch out of [38%, 62%] window: {pos_branch}/{total}"
    );
    assert!(
        (min_branch..=max_branch).contains(&neg_branch),
        "negative branch out of [38%, 62%] window: {neg_branch}/{total}"
    );

    for (bucket, count) in top2_hist.iter().enumerate() {
        assert!(
            *count >= 80 && *count <= 180,
            "top-2-bit bucket {bucket} imbalanced: {count}/{total}"
        );
    }
}

#[test]
fn test_base62_fixed_roundtrip_and_overflow_rejection() {
    let payload = [0xffu8; 64];
    let encoded = encode_base62_fixed(&payload, 86).expect("64xFF fits in 86 Base62 chars");
    assert_eq!(encoded.len(), 86);
    let decoded = decode_base62_fixed(&encoded, 64).expect("decode 64 bytes");
    assert_eq!(decoded.as_slice(), &payload);

    let overflow =
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    assert!(decode_base62_fixed(overflow, 64).is_err());
}

#[test]
fn test_stateless_zero_db_autopsy_across_all_tier1_profiles_and_tamper_rejection() {
    let mut rng = StdRng::seed_from_u64(0x51A7_E1E5_5C49_5A11u64);
    let kp = TaggantKeypair::generate();
    let wrong_kp = TaggantKeypair::generate();
    let pub_key_only = kp.pub_key;

    let host = "bastion-01.example.com";
    let path = "/srv/checkout/.env.staging";
    let branch = "release/2026-11";
    let epoch = 29_915_000u32;

    let expected_ctx = ProvenanceContext {
        profile_id: "openai-proj".to_string(),
        kind_code: 1,
        epoch_minutes: epoch,
        host: host.to_string(),
        path: path.to_string(),
        branch: branch.to_string(),
    };
    let (ht, pt, bt) = expected_ctx.compute_tags();

    let mut blob = String::new();
    for profile in [
        BaitProfile::OpenaiProj,
        BaitProfile::AnthropicApi,
        BaitProfile::GithubPat,
        BaitProfile::OpensshKey,
    ] {
        let minted = mint_canary(&mut rng, &pub_key_only, profile, host, path, branch, epoch)
            .expect("mint tier1 token");
        blob.push_str(&format!("{}={}\n", minted.env_var, minted.primary_secret));

        // 1-char mutation on non-PEM tokens must fail AEAD authentication
        if profile != BaitProfile::OpensshKey {
            let mut mutated = minted.primary_secret.clone();
            let last = mutated.pop().unwrap();
            let replacement = if last == 'A' { 'B' } else { 'A' };
            mutated.push(replacement);
            let bad_hits = stateless_autopsy_scan(&mutated, &kp.autopsy_sk).unwrap();
            assert!(
                bad_hits.is_empty(),
                "mutated {} token should fail AEAD",
                profile.id()
            );
        }
    }

    // Wrong autopsy key decrypts zero tokens
    let wrong_hits = stateless_autopsy_scan(&blob, &wrong_kp.autopsy_sk).unwrap();
    assert!(wrong_hits.is_empty());

    // Zero-DB offline autopsy recovers all 4 Tier-1 tokens with exact tags
    let hits = run_autopsy(&blob, &kp.autopsy_sk, None).expect("offline autopsy succeeds");
    assert_eq!(hits.len(), 4);

    for hit in &hits {
        assert_eq!(hit.epoch_minutes, Some(epoch));
        assert!(hit.resolved_host.is_none());
        if hit.profile == "github-pat" {
            assert_eq!(hit.host_tag_hex, hex::encode(&ht[..2]));
            assert_eq!(hit.path_tag_hex, hex::encode(&pt[..3]));
            assert_eq!(hit.branch_tag_hex, hex::encode(&bt[..2]));
        } else {
            assert_eq!(hit.host_tag_hex, hex::encode(ht));
            assert_eq!(hit.path_tag_hex, hex::encode(pt));
            assert_eq!(hit.branch_tag_hex, hex::encode(bt));
        }
    }

    // Profile AAD binding prevents cross-profile replay of raw 64B capsules
    let raw_cap = seal_capsule_64(&mut rng, &pub_key_only, &expected_ctx).unwrap();
    assert!(open_capsule_64(&kp.autopsy_sk, "anthropic-api", &raw_cap).is_err());
}

#[test]
fn test_tier2_crc32_vault_encryption_and_merkle_alert_tamper_detection() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("vault").join("taggant.db");
    let passphrase = b"correct-horse-taggant-staple-99";

    let mut vault = TaggantVault::open_with_passphrase(&db_path, passphrase, true).unwrap();
    let pub_key = vault.public_key();
    let mut rng = StdRng::seed_from_u64(0x9988_7766_5544_3322u64);

    let ghp = mint_canary(
        &mut rng,
        &pub_key,
        BaitProfile::GithubClassic,
        "bastion-01.example.com",
        "/srv/checkout/.env.staging",
        "main",
        29_915_100,
    )
    .unwrap();
    assert!(verify_github_classic_crc(&ghp.primary_secret));

    let mut bad_ghp = ghp.primary_secret.clone();
    let tail = bad_ghp.pop().unwrap();
    bad_ghp.push(if tail == '0' { '1' } else { '0' });
    assert!(!verify_github_classic_crc(&bad_ghp));

    let rec = CanaryRecord {
        profile: ghp.profile.id().to_string(),
        env_var: ghp.env_var.clone(),
        host: "bastion-01.example.com".to_string(),
        target_path: "/srv/checkout/.env.staging".to_string(),
        branch: "main".to_string(),
        epoch_minutes: ghp.epoch_minutes,
        host_tag_hex: ghp.host_tag_hex.clone(),
        path_tag_hex: ghp.path_tag_hex.clone(),
        branch_tag_hex: ghp.branch_tag_hex.clone(),
        token_preview: "ghp_preview".to_string(),
        created_at: "2026-11-18T00:00:00Z".to_string(),
    };
    vault.record_canary(&rec, &ghp.primary_secret).unwrap();

    // Also verify Tier-2 lookup & context enrichment via run_autopsy
    let hits = run_autopsy(&ghp.primary_secret, vault.autopsy_secret(), Some(&vault)).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].resolved_path.as_deref(),
        Some("/srv/checkout/.env.staging")
    );

    // Append 2 Merkle alerts and verify intact chain
    vault
        .append_tripwire_alert(NewTripwireAlert {
            source_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            request_path: "/v1/ping/probe1".to_string(),
            profile: "openai-proj".to_string(),
            token_preview: "sk-proj-123".to_string(),
            host_label: "bastion-01.example.com".to_string(),
            target_path_label: "/srv/checkout/.env.staging".to_string(),
            branch_label: "main".to_string(),
        })
        .unwrap();
    vault
        .append_tripwire_alert(NewTripwireAlert {
            source_ip: "127.0.0.1".to_string(),
            method: "POST".to_string(),
            request_path: "/v1/ping/probe2".to_string(),
            profile: "anthropic-api".to_string(),
            token_preview: "sk-ant-456".to_string(),
            host_label: "bastion-01.example.com".to_string(),
            target_path_label: "/srv/checkout/.env.staging".to_string(),
            branch_label: "main".to_string(),
        })
        .unwrap();
    let chain = vault.verify_alert_chain().unwrap();
    assert!(chain.valid);
    assert_eq!(chain.total_alerts, 2);

    // Verify ACL helper runs cleanly on Windows/Unix
    enforce_vault_and_sidecar_acls(&db_path).unwrap();
    drop(vault);

    // Raw DB bytes must contain zero plaintext secret paths or token literals
    let raw_db = std::fs::read(&db_path).unwrap();
    let raw_lossy = String::from_utf8_lossy(&raw_db);
    assert!(!raw_lossy.contains("/srv/checkout/.env.staging"));
    assert!(!raw_lossy.contains(&ghp.primary_secret));

    // Wrong passphrase fails closed
    assert!(TaggantVault::open_with_passphrase(&db_path, b"wrong-pass", true).is_err());

    // Tampering 1 byte of tripwire_alerts row breaks verify_alert_chain()
    {
        let raw_conn = Connection::open(&db_path).unwrap();
        raw_conn
            .execute(
                "UPDATE tripwire_alerts SET profile = 'tampered-profile' WHERE seq = 1",
                [],
            )
            .unwrap();
    }
    let reopened = TaggantVault::open_with_passphrase(&db_path, passphrase, true).unwrap();
    assert!(reopened.verify_alert_chain().is_err());
}

#[tokio::test]
async fn test_end_to_end_seed_fleet_verify_and_loopback_tripwire() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault").join("taggant.db");
    let honeypot_dir = dir.path().join("repo-canary");
    std::fs::create_dir_all(&honeypot_dir).unwrap();

    let vault = TaggantVault::open_with_passphrase(&vault_path, b"fleet-pass-123", true).unwrap();
    let pub_key = vault.public_key();

    // Reject non-loopback binds (0.0.0.0)
    let non_loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let shared_for_err = Arc::new(Mutex::new(vault));
    let (_tx_err, rx_err) = watch::channel(false);
    assert!(
        serve_loopback_tripwire(
            non_loopback,
            Arc::clone(&shared_for_err),
            None,
            rx_err,
            false
        )
        .await
        .is_err()
    );

    // Spin up ephemeral 127.0.0.1:0 loopback tripwire
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_handle = tokio::spawn(serve_loopback_tripwire(
        loopback,
        Arc::clone(&shared_for_err),
        Some(ready_tx),
        shutdown_rx,
        false,
    ));

    let bound_addr = ready_rx.await.expect("listener bound");

    // Seed honeypot directory while vault is locked via scope
    let seed_report = {
        let mut guard = shared_for_err.lock().unwrap();
        seed_target(
            &honeypot_dir,
            &pub_key,
            Some(&mut guard),
            "bastion-01.example.com",
            "main",
            Some(bound_addr.port()),
        )
        .unwrap()
    };
    assert_eq!(seed_report.minted_count, 6);
    let tripwire_url = seed_report.tripwire_url.expect("tripwire URL emitted");
    let ping_path = tripwire_url
        .split(&format!(":{}", bound_addr.port()))
        .nth(1)
        .expect("URL path");

    // Fleet scan sees 5 verified canaries (OpenAI x2, Anthropic, GitHub PAT, GitHub Classic, AWS AKIA = 6)
    {
        let guard = shared_for_err.lock().unwrap();
        let fleet =
            verify_fleet_directory(&honeypot_dir, Some(guard.autopsy_secret()), Some(&guard))
                .unwrap();
        assert_eq!(fleet.verified_canaries.len(), 6);
        assert!(fleet.unregistered_secrets.is_empty());
    }

    // Plant an unregistered decoy lookalike -> verify-fleet flags it!
    let fake_leak_file = honeypot_dir.join("real_leak.env");
    let fake_token = format!("sk-proj-{}", "A".repeat(86));
    std::fs::write(&fake_leak_file, format!("LEAK={fake_token}\n")).unwrap();
    {
        let guard = shared_for_err.lock().unwrap();
        let fleet =
            verify_fleet_directory(&honeypot_dir, Some(guard.autopsy_secret()), Some(&guard))
                .unwrap();
        assert_eq!(fleet.verified_canaries.len(), 6);
        assert_eq!(fleet.unregistered_secrets.len(), 1);
    }

    // Trigger loopback tripwire over TCP HTTP GET
    let mut stream = TcpStream::connect(bound_addr).await.unwrap();
    let req = format!(
        "GET {ping_path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        bound_addr.port()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("401 Unauthorized"));

    let _ = shutdown_tx.send(true);
    let _ = srv_handle.await;

    let guard = shared_for_err.lock().unwrap();
    let alerts = guard.list_tripwire_alerts(10).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].profile, "openai-proj");
    assert_eq!(alerts[0].host_label, "bastion-01.example.com");
    assert!(guard.verify_alert_chain().unwrap().valid);
}

#[test]
fn test_ratatui_test_backend_snapshot_and_cwe150_ansi_sanitization() {
    // Verify CWE-150 strips CSI/OSC escapes and Bell controls while keeping tabs/newlines
    let poisoned = "bastion-01\x1b[31mFAKE\x07\x1b]0;pwn\x07.example.com";
    let clean = sanitize_terminal_str(poisoned);
    assert!(!clean.contains('\x1b'));
    assert!(!clean.contains('\x07'));
    assert_eq!(clean, "bastion-01[31mFAKE]0;pwn.example.com");

    let mut vault = TaggantVault::open_in_memory_for_test(b"tui-pass").unwrap();
    let rec = CanaryRecord {
        profile: "openai-proj".to_string(),
        env_var: "OPENAI_API_KEY".to_string(),
        host: poisoned.to_string(),
        target_path: "/srv/checkout/.env.staging".to_string(),
        branch: "main".to_string(),
        epoch_minutes: 29_915_200,
        host_tag_hex: "aabbcc".to_string(),
        path_tag_hex: "11223344".to_string(),
        branch_tag_hex: "55667788".to_string(),
        token_preview: "sk-proj-abc...xyz".to_string(),
        created_at: "2026-11-18T00:00:00Z".to_string(),
    };
    vault.record_canary(&rec, "sk-proj-dummy").unwrap();
    vault
        .append_tripwire_alert(NewTripwireAlert {
            source_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            request_path: "/v1/ping/test\x1b[2J".to_string(),
            profile: "openai-proj".to_string(),
            token_preview: "sk-proj-abc...xyz".to_string(),
            host_label: "bastion-01.example.com".to_string(),
            target_path_label: "/srv/checkout/.env.staging".to_string(),
            branch_label: "main".to_string(),
        })
        .unwrap();

    let mut app = TaggantTuiApp::new(
        ":memory:".to_string(),
        vault.public_key_b64(),
        vault.list_canaries().unwrap(),
        Vec::new(),
        vault.list_tripwire_alerts(20).unwrap(),
        vault.verify_alert_chain().unwrap(),
    );
    app.next_pane();
    app.next_pane();
    app.prev_pane();
    app.prev_pane();

    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("TAGGANT v0.1.0"));
    assert!(rendered.contains("MERKLE CHAIN: VERIFIED"));
    assert!(rendered.contains("PLANTED CANARY INVENTORY"));
    assert!(rendered.contains("OFFLINE ELLIGATOR2 AUTOPSY INSPECTOR"));
    assert!(rendered.contains("BLAKE3 MERKLE LOOPBACK TRIPWIRE ALERTS"));
    assert!(!rendered.contains('\x1b'));
}

#[test]
fn test_keypair_deterministic_seed_matches_static_secret() {
    let raw = [0x11u8; 32];
    let kp = TaggantKeypair::from_secret_bytes(raw);
    let sk2 = StaticSecret::from(raw);
    assert_eq!(kp.pub_key.as_bytes(), PublicKey::from(&sk2).as_bytes());
}
