//! Loopback-only HTTP decoy tripwire listener (`taggant watch`).
//!
//! Security Invariants:
//! - **Strict Loopback Binding:** Refuses any non-loopback `SocketAddr` (`0.0.0.0`, LAN IP, etc.).
//! - **Bounded Header/Body Reads:** Enforces `16 KiB` request cap and `5s` socket timeout.
//! - **Tamper-Evident Alert Logging:** Any embedded Tier-1 or Tier-2 token triggers an offline
//!   autopsy and appends a `BLAKE3`-chained `TripwireAlert` into `taggant.db`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};

use crate::ops::scan::run_autopsy;
use crate::vault::{NewTripwireAlert, TaggantVault, TripwireAlert};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const HTTP_401_DECOY: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 109\r\n\r\n{\"error\":{\"message\":\"Incorrect API key provided or quota exceeded.\",\"type\":\"invalid_request_error\",\"code\":\"invalid_api_key\"}}";

/// Parse the HTTP request line into `(method, path)`.
fn parse_request_line(raw: &str) -> (String, String) {
    let first_line = raw.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("UNKNOWN").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    (method, path)
}

async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    vault: Arc<Mutex<TaggantVault>>,
) -> Result<Option<TripwireAlert>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let read_result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            let take = n.min(MAX_REQUEST_BYTES.saturating_sub(buf.len()));
            buf.extend_from_slice(&chunk[..take]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_REQUEST_BYTES {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;

    let _ = read_result;
    let raw_req = String::from_utf8_lossy(&buf).to_string();
    let (method, request_path) = parse_request_line(&raw_req);

    let recorded_alert = {
        let mut guard = vault
            .lock()
            .map_err(|_| anyhow!("TaggantVault mutex poisoned inside loopback tripwire"))?;
        let hits = run_autopsy(&raw_req, guard.autopsy_secret(), Some(&guard))?;
        if let Some(hit) = hits.into_iter().next() {
            let alert = guard.append_tripwire_alert(NewTripwireAlert {
                source_ip: peer.ip().to_string(),
                method,
                request_path,
                profile: hit.profile,
                token_preview: hit.token_preview,
                host_label: hit.resolved_host.unwrap_or(hit.host_tag_hex),
                target_path_label: hit.resolved_path.unwrap_or(hit.path_tag_hex),
                branch_label: hit.resolved_branch.unwrap_or(hit.branch_tag_hex),
            })?;
            Some(alert)
        } else {
            let alert = guard.append_tripwire_alert(NewTripwireAlert {
                source_ip: peer.ip().to_string(),
                method,
                request_path,
                profile: "unattributed-probe".to_string(),
                token_preview: "(no-taggant-token)".to_string(),
                host_label: "loopback".to_string(),
                target_path_label: "unknown".to_string(),
                branch_label: "unknown".to_string(),
            })?;
            Some(alert)
        }
    };

    let _ = stream.write_all(HTTP_401_DECOY).await;
    let _ = stream.shutdown().await;
    Ok(recorded_alert)
}

/// Bind strictly to a loopback `SocketAddr` and serve until `shutdown_rx` receives `true`.
pub async fn serve_loopback_tripwire(
    bind_addr: SocketAddr,
    vault: Arc<Mutex<TaggantVault>>,
    ready_tx: Option<oneshot::Sender<SocketAddr>>,
    mut shutdown_rx: watch::Receiver<bool>,
    log_to_stderr: bool,
) -> Result<()> {
    if !bind_addr.ip().is_loopback() {
        return Err(anyhow!(
            "refusing to bind tripwire on non-loopback address {} (loopback 127.0.0.1 / ::1 required)",
            bind_addr.ip()
        ));
    }

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind Taggant loopback tripwire at {bind_addr}"))?;
    let local_addr = listener.local_addr()?;
    if let Some(tx) = ready_tx {
        let _ = tx.send(local_addr);
    }

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let vault_ref = Arc::clone(&vault);
                tokio::spawn(async move {
                    match handle_client(stream, peer, vault_ref).await {
                        Ok(Some(alert)) if log_to_stderr => {
                            eprintln!(
                                "[TAGGANT:TRIPWIRE] seq={} profile={} host={} path={} hash={}...",
                                alert.seq,
                                alert.profile,
                                alert.host_label,
                                alert.target_path_label,
                                &alert.entry_hash[..12]
                            );
                        }
                        Err(err) if log_to_stderr => {
                            eprintln!("[TAGGANT:TRIPWIRE:ERR] {err}");
                        }
                        _ => {}
                    }
                });
            }
        }
    }

    Ok(())
}
