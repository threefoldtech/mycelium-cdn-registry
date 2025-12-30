use std::{net::SocketAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

/// `mycdnctl` configuration.
///
/// This configuration defines:
/// 1) how shards are stored (Hero Redis backends)
/// 2) how metadata is stored (Holochain via the **HoloKVS CLI**)
///
/// ## Shards (Hero Redis)
/// Each configured backend receives one shard.
/// Reed-Solomon requires:
/// - `required_shards >= 1`
/// - `required_shards <= backends.len()`
///
/// ## Metadata (HoloKVS CLI)
/// Metadata is stored as a key-value entry in the HoloKVS hApp:
/// - key: a stable string key (recommended: lowercase hex of the 16-byte encrypted metadata hash)
/// - value: the encrypted metadata bytes encoded as a `String` (lowercase hex)
///
/// The HoloKVS POC CLI (`holokvs`) handles:
/// - connecting to the conductor via admin/app websockets
/// - issuing an app authentication token
/// - nonce fetching (`get_next_nonce`)
/// - canonical VXEdDSA signing using an X25519 key for `set_value`
///
/// `mycdnctl` shells out to that CLI rather than integrating a Holochain client directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Amount of shards we need (at minimum) to recover.
    pub required_shards: u16,

    /// Shard storage backends (Hero Redis).
    #[serde(default)]
    pub backends: Vec<ShardBackend>,

    /// Metadata storage configuration.
    pub metadata: MetadataStorage,
}

impl Config {
    /// Total number of shard backends configured.
    pub fn shard_backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Basic sanity checks for uploader usage.
    pub fn validate_for_upload(&self) -> Result<(), String> {
        let n = self.shard_backend_count();
        if n == 0 {
            return Err("no shard backends configured (set one or more [[backends]])".to_string());
        }
        if self.required_shards == 0 {
            return Err("required_shards must be >= 1".to_string());
        }
        if (self.required_shards as usize) > n {
            return Err(format!(
                "required_shards ({}) is greater than number of shard backends ({n})",
                self.required_shards
            ));
        }

        // Metadata storage validation
        match &self.metadata {
            MetadataStorage::HoloKvs(cfg) => cfg.validate_for_write()?,
        }

        Ok(())
    }
}

/// A shard storage backend (Hero Redis only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShardBackend {
    /// Hero Redis backend.
    ///
    /// Hero Redis is Redis protocol compatible, but authentication is typically:
    /// - session token via `AUTH <token>`, or
    /// - Ed25519 signature flow `CHALLENGE` -> `TOKEN` -> `AUTH` (Hero Redis specific).
    HeroRedis {
        host: SocketAddr,
        /// Database number to `SELECT` after authentication.
        db: u16,
        /// Optional auth.
        ///
        /// - `None`: no authentication attempted (only works if server allows it)
        /// - `Token`: client uses `AUTH <token>`
        /// - `PrivateKey`: client performs `CHALLENGE`/`TOKEN`/`AUTH` using the private key
        auth: Option<HeroRedisAuth>,
    },
}

/// Authentication material for Hero Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeroRedisAuth {
    /// Session token used with `AUTH <token>`.
    Token { token: String },

    /// Ed25519 private key (hex-encoded, 64 chars / 32 bytes) used to perform:
    /// `CHALLENGE` -> `TOKEN` -> `AUTH`.
    PrivateKey { private_key: String },
}

/// Metadata storage backend configuration.
///
/// Today we support storing encrypted metadata blobs into Holochain via the HoloKVS POC hApp,
/// **by invoking the `holokvs` CLI**.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetadataStorage {
    /// Store encrypted metadata blobs using the HoloKVS CLI.
    ///
    /// The CLI is expected to support:
    /// - `holokvs set <key> <value> --x25519-sk <sk_hex> ...`
    /// - `holokvs get <key> ...`
    HoloKvs(HoloKvsCliConfig),
}

/// Configuration for metadata storage via the `holokvs` CLI.
///
/// This is intentionally aligned with the CLI flags/options rather than the underlying Holochain API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoloKvsCliConfig {
    /// Path to the `holokvs` CLI binary.
    ///
    /// - If set to `"holokvs"` (default), it will be resolved via `$PATH`.
    /// - You can also set an absolute or relative path, e.g. `"./holopoc/cli/target/release/holokvs"`.
    #[serde(default = "default_holokvs_bin")]
    pub bin: PathBuf,

    /// Websocket host for admin/app interfaces (default: 127.0.0.1).
    #[serde(default = "default_holo_host")]
    pub host: String,

    /// Admin websocket port (default: 8888).
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,

    /// App websocket port (optional).
    ///
    /// If omitted, the CLI is expected to obtain/attach an app interface via the admin websocket.
    #[serde(default)]
    pub app_port: Option<u16>,

    /// Installed app ID to connect to (default: "kv_store").
    #[serde(default = "default_app_id")]
    pub app_id: String,

    /// Optional key prefix for namespacing metadata keys in the global keyspace.
    ///
    /// Example: `"mycelium-cdn/meta/"`.
    #[serde(default)]
    pub key_prefix: Option<String>,

    /// X25519 private key (32 bytes hex, 64 hex chars; optional "0x" prefix) used to sign writes.
    ///
    /// This is required for `mycdnctl upload` to store metadata.
    pub writer_x25519_sk_hex: Option<String>,
}

impl HoloKvsCliConfig {
    /// Validates that the config is usable for writes (set/delete).
    pub fn validate_for_write(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("metadata.host must be non-empty".to_string());
        }
        if self.admin_port == 0 {
            return Err("metadata.admin_port must be non-zero".to_string());
        }
        if self.app_id.trim().is_empty() {
            return Err("metadata.app_id must be non-empty".to_string());
        }

        let Some(sk) = &self.writer_x25519_sk_hex else {
            return Err("metadata.writer_x25519_sk_hex must be set to write metadata".to_string());
        };

        validate_x25519_sk_hex(sk).map_err(|msg| format!("metadata.writer_x25519_sk_hex {msg}"))?;

        Ok(())
    }
}

fn default_holokvs_bin() -> PathBuf {
    PathBuf::from("holokvs")
}

fn default_holo_host() -> String {
    "127.0.0.1".to_string()
}

fn default_admin_port() -> u16 {
    8888
}

fn default_app_id() -> String {
    "kv_store".to_string()
}

fn validate_x25519_sk_hex(s: &str) -> Result<(), String> {
    let mut s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        s = rest;
    }
    if s.len() != 64 {
        return Err("must be 64 hex chars (32 bytes)".to_string());
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("must contain only hex characters".to_string());
    }
    Ok(())
}
