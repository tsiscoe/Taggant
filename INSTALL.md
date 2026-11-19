# Installing Taggant

Installing Taggant takes under two minutes once Rust is present. Figuring out six months after a breach which staging machine a leaked API key wandered off from without cryptographic provenance takes substantially longer and usually involves an external forensics retainer.

## Prerequisites

- **Rust `1.85+`** (2024 Edition) via [rustup.rs](https://rustup.rs/).
- **Supported platforms:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

`rusqlite` compiles SQLite bundled from source on the first build, so there are no external OpenSSL or SQLite DLL dependencies to hunt down—just give `cargo` a minute to chew through the C library.

## Build from Source

```bash
git clone https://github.com/tsiscoe/Taggant.git
cd Taggant
cargo build --release
```

The binary lands at `target/release/taggant` (`target/release/taggant.exe` on Windows). Install it onto your `PATH` with:

```bash
cargo install --path .
```

## Environment Variables

Only your custody/autopsy workstation needs `TAGGANT_PASSPHRASE` or `TAGGANT_AUTOPSY_KEY`. Untrusted seeding hosts only ever need `TAGGANT_PUB_KEY` (or a `.pub` file).

| Variable | What It Does | Default |
| :--- | :--- | :--- |
| `TAGGANT_VAULT` | Path to the encrypted SQLite WAL custody vault. | `~/.config/taggant/taggant.db` (`%APPDATA%\taggant\taggant.db` on Windows) |
| `TAGGANT_PASSPHRASE` | Master vault passphrase for non-interactive CI runs. | Interactive prompt, or OS keyring with `--keyring` |
| `TAGGANT_PUB_KEY` | Public key (`taggant-pub-v1:...`) for vaultless `mint` / `seed`. | Loaded from unlocked vault if omitted |
| `TAGGANT_AUTOPSY_KEY` | Raw `taggant-sec-v1:...` key for air-gapped zero-DB `autopsy`. | Loaded from unlocked vault if omitted |

## Verify the Install

```bash
taggant --version
taggant --keyring init --export-pub ./taggant.pub
```

If `init` prints your vault path and a `taggant-pub-v1:` key, drop that public key on any machine you don't fully trust and start seeding decoys with `taggant seed --pub-key ./taggant.pub`. Keep `taggant.db` and `taggant-sec-v1:` far away from that machine.
