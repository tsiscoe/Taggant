# Changelog

All notable changes to **Taggant** (`taggant`) are documented here.

## [0.1.0] - 2026-11-18

Initial public release: asymmetric honeytokens that outlive the machine they were stolen from.

### Added
- **Constant-time $\mathbb{F}_{2^{255}-19}$ & Two-Branch `Elligator2` (`src/crypto/fe25519.rs`, `src/crypto/elligator.rs`).** Radix-$2^{51}$ field arithmetic implementing `std::ops::{Add, Sub, Neg, Mul}`, Atkin square roots, and Curve25519 `Elligator2` with randomized $r_1 / r_2$ preimage selection and top-2-bit uniformity padding.
- **HPKE-Style Provenance Capsules (`src/crypto/capsule.rs`).** `64B` and compact `60B` `X25519` + `HKDF-SHA256` + `ChaCha20-Poly1305` capsules carrying authenticated `epoch_minutes`, `host_tag`, `path_tag`, and `branch_tag` payloads directly inside leaked tokens.
- **Six Credential Bait Profiles (`src/formats/mod.rs`).** Tier-1 stateless `Elligator2` (`openai-proj`, `anthropic-api`, `github-pat`, RFC-framed `openssh-key`) and Tier-2 vault-indexed (`github-classic` with tableless IEEE `CRC32`, `aws-iam-pair`), plus fixed-width Base62 encode/decode.
- **Encrypted Custody Vault & `BLAKE3` Merkle Alert Chain (`src/vault/mod.rs`).** `Argon2id` (`64 MiB, t=3, p=4`) + `HKDF-SHA256` + `XChaCha20-Poly1305` SQLite WAL vault (`rusqlite 0.42.0`) encrypting `TaggantAutopsyKey`, canary records, context tags, and `tripwire_alerts` payloads on disk (`BEGIN IMMEDIATE`, `PRAGMA secure_delete = ON`, fail-closed `icacls` / `0600` ACLs).
- **CLI, Stealth Loopback Trap & 3-Pane TUI (`src/cli.rs`, `src/ops/`, `src/tui/`).** Subcommands `init`, `mint`, `seed` (with stealth `INTERNAL_TELEMETRY_PING_URL`), `autopsy`, `verify-fleet`, strict `127.0.0.1` HTTP `watch`, `export-key`, and a `CWE-150` ANSI-sanitized `Ratatui v0.30` dashboard.
- **CI & Verification Suite.** Cross-platform GitHub Actions workflow (`.github/workflows/ci.yml`), 512-case `proptest!` bijection, 512-sample uniformity check, vault tamper detection, ephemeral HTTP tripwire test, and `TestBackend` snapshot suite.
