use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Uploader configuration (Hero Redis only).
///
/// This config defines where encoded shards are stored. Each configured backend receives one shard.
///
/// Notes:
/// - `required_shards` must be `>= 1`
/// - `required_shards` must be `<= backends.len()`
///
/// ## Example
/// ```toml
/// required_shards = 3
///
/// [[backends]]
/// kind = "hero_redis"
/// host = "10.0.0.10:6379"
/// db = 7
///
/// [[backends]]
/// kind = "hero_redis"
/// host = "10.0.0.11:6379"
/// db = 7
///
/// # Optional auth
/// [[backends]]
/// kind = "hero_redis"
/// host = "10.0.0.12:6379"
/// db = 7
/// auth = { type = "token", token = "your-session-token" }
///
/// # Or: Ed25519 private key (client performs CHALLENGE/TOKEN/AUTH)
/// # Note: private_key must be 64 hex chars (32 bytes).
/// [[backends]]
/// kind = "hero_redis"
/// host = "10.0.0.13:6379"
/// db = 7
/// auth = { type = "private_key", private_key = "e5f6a7b8... (64 hex chars total)" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Amount of shards we need (at minimum) to recover.
    pub required_shards: u16,

    /// Shard storage backends (Hero Redis only).
    #[serde(default)]
    pub backends: Vec<ShardBackend>,
}

impl Config {
    /// Returns the configured shard backends.
    pub fn shard_backends(&self) -> Vec<ShardBackend> {
        self.backends.clone()
    }

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
