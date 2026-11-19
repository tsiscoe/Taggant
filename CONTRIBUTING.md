# Contributing to Taggant

Every pull request has to clear the CI gates below before any test runner bothers waking up. They aren't aesthetic preferences; they are the minimum load-bearing walls of a cryptographic crate.

## The Gates

1. **Zero `unsafe` code.** `#![forbid(unsafe_code)]` is locked in both `Cargo.toml` and `src/lib.rs`. If your feature needs `unsafe`, it belongs in another repository.
2. **Formatting.** `cargo fmt --all -- --check` must return zero diff.
3. **Strict Lints.** `cargo clippy --all-targets -- -D warnings` must pass with zero warnings across Windows, Linux, and macOS.
4. **Tests & Property Proofs.** `cargo test` must pass 100%, including the 512-case `Elligator2` `proptest!` bijection, the 512-sample $\varepsilon = \pm 1$ uniformity test, encrypted SQLite raw-byte grep checks, loopback HTTP tripwire tests, and headless `Ratatui` `TestBackend` snapshot verification.
5. **Sterile Test Fixtures.** Never commit literal email addresses, private subnets, raw API keys, or local home-directory paths into source, docs, or tests. Construct decoy test inputs dynamically at runtime via `mint_canary` or `format!`, and verify `loom audit --fail-on-leak` reports **0 findings**.

## Running the Gates Locally

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Reporting a Vulnerability

Do not open a public GitHub issue detailing a side-channel or curve-bias flaw with a working exploit attached. Contact the maintainer privately via GitHub Security Advisories with a minimal reproduction.
