use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// `mycdnctl` configuration.
///
/// This configuration defines:
/// 1) how shards are stored (Hero Redis backends)
/// 2) how metadata is stored (Holochain via direct integration with the HoloKVS hApp)
///
/// ## Shards (Hero Redis)
/// Each configured backend receives one shard.
/// Reed-Solomon requires:
/// - `required_shards >= 1`
/// - `required_shards <= backends.len()`
///
/// ## Metadata (Holochain / HoloKVS)
/// Metadata is stored as a key-value entry in the HoloKVS hApp:
/// - key: a stable string key (recommended: lowercase hex of the 16-byte encrypted metadata hash)
/// - value: the encrypted metadata bytes encoded as a `String` (lowercase hex)
///
/// Direct integration expectations (based on the holopoc POC behavior):
/// - Connect to the Holochain conductor's Admin WebSocket (`host:admin_port`)
/// - Issue an app authentication token for `app_id`
/// - Connect to the App WebSocket (use `app_port` if provided; otherwise obtain/attach via admin)
/// - Determine a provisioned cell for the app
/// - Perform zome calls to the coordinator zome (default: `kv_store`)
///   - `get_next_nonce(key: String) -> u32`
///   - `get_state(key: String) -> Option<GetStateOutput>` (to preserve ACL on updates)
///   - `set_value(input: WriteInput) -> SetOutput`
/// - Writes must be signed exactly as the integrity zome expects (VXEdDSA, Signal spec),
///   using an X25519 keypair and including the correct ACL bytes in the signed payload.
///
/// NOTE: This config schema intentionally does NOT include any path to an external `holokvs` binary.
/// `mycdnctl` should integrate with Holochain directly.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetadataStorage {
    /// Store encrypted metadata blobs in Holochain using the HoloKVS POC hApp (direct integration).
    HoloKvs(HoloKvsConfig),
}

/// Configuration for metadata storage via direct Holochain integration with the HoloKVS hApp.
///
/// This schema is aligned with the conductor connection details and the POC hApp layout.
///
/// Zome function names are hardcoded in `mycdnctl` to match the holopoc defaults.
///
/// Important constraint:
/// - The HoloKVS POC stores values as `String`, so binary metadata is stored as lowercase hex text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoloKvsConfig {
    /// Websocket host for admin/app interfaces (default: 127.0.0.1).
    #[serde(default = "default_holo_host")]
    pub host: String,

    /// Admin websocket port (default: 8888).
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,

    /// App websocket port (optional).
    ///
    /// If omitted, the implementation should obtain/attach an app interface via the admin websocket.
    #[serde(default)]
    pub app_port: Option<u16>,

    /// Installed app ID to connect to (default: "kv_store").
    #[serde(default = "default_app_id")]
    pub app_id: String,

    /// Coordinator zome name (default: "kv_store").
    #[serde(default = "default_zome_name")]
    pub zome_name: String,

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

impl HoloKvsConfig {
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
        if self.zome_name.trim().is_empty() {
            return Err("metadata.zome_name must be non-empty".to_string());
        }

        let Some(sk) = &self.writer_x25519_sk_hex else {
            return Err("metadata.writer_x25519_sk_hex must be set to write metadata".to_string());
        };

        validate_x25519_sk_hex(sk).map_err(|msg| format!("metadata.writer_x25519_sk_hex {msg}"))?;

        Ok(())
    }
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

fn default_zome_name() -> String {
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
