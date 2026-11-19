//! **Taggant** (`taggant`) — Asymmetric `Elligator2` Cryptographic Honeytoken Seeder,
//! Stateless Offline Autopsy Engine, Fleet Sterility Gate & Loopback Tripwire.
//!
//! Enforces `#![forbid(unsafe_code)]` across the entire crate.

#![forbid(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod formats;
pub mod ops;
pub mod tui;
pub mod vault;
