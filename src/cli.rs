//! Clap v4 CLI surface for **Taggant** (`taggant v0.1.0`).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "taggant",
    version,
    about = "Asymmetric Elligator2 cryptographic honeytoken seeder, stateless offline autopsy engine, fleet sterility gate, and loopback tripwire"
)]
pub struct Cli {
    /// Path to encrypted SQLite WAL vault (`taggant.db`).
    #[arg(long, env = "TAGGANT_VAULT", global = true)]
    pub vault: Option<PathBuf>,

    /// Store or retrieve vault passphrase via the native OS credential manager.
    #[arg(long, global = true)]
    pub keyring: bool,

    /// Emit machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize an encrypted Taggant custody vault and generate an X25519 keypair.
    Init {
        /// Optional path to write the safe-to-distribute `taggant-pub-v1:...` public key.
        #[arg(long)]
        export_pub: Option<PathBuf>,
    },

    /// Mint a single honeytoken using ONLY `TaggantPubKey` (or an unlocked vault).
    Mint {
        /// Bait profile: openai-proj, anthropic-api, github-pat, openssh-key, github-classic, aws-iam-pair.
        #[arg(long, default_value = "openai-proj")]
        profile: String,

        /// Base64/Hex `TaggantPubKey` string or path to `.pub` file (no decryption privilege needed).
        #[arg(long, env = "TAGGANT_PUB_KEY")]
        pub_key: Option<String>,

        /// Host label embedded in provenance hash tags.
        #[arg(long)]
        host: Option<String>,

        /// Target path label embedded in provenance hash tags.
        #[arg(long, default_value = ".env.staging")]
        path: String,

        /// Git branch or agent label embedded in provenance hash tags.
        #[arg(long)]
        branch: Option<String>,

        /// Record minted canary metadata into the encrypted vault (ignored unless vault unlocked).
        #[arg(long)]
        record: bool,
    },

    /// Seed realistic decoy credentials into a `.env` file or directory.
    Seed {
        /// Target file path or directory (directory writes `<target>/.env.staging`).
        #[arg(long, default_value = ".")]
        target: PathBuf,

        /// Optional `TaggantPubKey` string or file for vaultless seeding on untrusted hosts.
        #[arg(long, env = "TAGGANT_PUB_KEY")]
        pub_key: Option<String>,

        /// Override host label embedded in provenance tags.
        #[arg(long)]
        host: Option<String>,

        /// Override Git branch label embedded in provenance tags.
        #[arg(long)]
        branch: Option<String>,

        /// Also plant a loopback `INTERNAL_TELEMETRY_PING_URL=http://127.0.0.1:<PORT>/v1/ping/<canary>`.
        #[arg(long)]
        with_tripwire_port: Option<u16>,
    },

    /// Perform strictly offline `Elligator2` capsule autopsy over a token string, file, or `-` (stdin).
    Autopsy {
        /// Suspect token literal, path to a file/log to scan, or `-` to read stdin.
        input: String,

        /// Raw `TaggantAutopsyKey` (hex or Base64) for zero-DB offline decryption without `taggant.db`.
        #[arg(long, env = "TAGGANT_AUTOPSY_KEY")]
        secret_key: Option<String>,
    },

    /// Scan a repository and distinguish verified Taggant canaries from unregistered secret leaks.
    VerifyFleet {
        /// Directory or file root to scan.
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Optional raw `TaggantAutopsyKey` (hex or Base64) for vaultless verification.
        #[arg(long, env = "TAGGANT_AUTOPSY_KEY")]
        secret_key: Option<String>,

        /// Exit non-zero even when only verified Taggant canaries are present.
        #[arg(long)]
        fail_on_any: bool,
    },

    /// Start the strictly loopback `127.0.0.1` HTTP canary tripwire listener.
    Watch {
        /// Loopback socket address (`127.0.0.1:<port>` or `[::1]:<port>`).
        #[arg(long, default_value = "127.0.0.1:19470")]
        bind: SocketAddr,
    },

    /// Launch the 3-pane Ratatui v0.30 custody, offline autopsy, and Merkle alert dashboard.
    Tui {
        /// Optional suspect log or file path to inspect inside Pane 2 on startup.
        #[arg(long)]
        autopsy_file: Option<PathBuf>,
    },

    /// Export the seeding public key or (with explicit flag) air-gapped autopsy secret key.
    ExportKey {
        /// Export the raw `taggant-sec-v1:<hex>` autopsy secret key for zero-DB offline recovery.
        #[arg(long)]
        autopsy_secret: bool,
    },
}
