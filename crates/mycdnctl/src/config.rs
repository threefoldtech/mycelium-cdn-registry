use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Configuration for zdbs to use when uploading files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Amount of shards we need (at minimum) to recover.
    pub required_shards: u16,
    /// List of 0-db instances to connect to and upload shards. One shard is send to every instance
    /// in this list.
    pub zdbs: Vec<Zdb>,
}

/// Connection info for a 0-db backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zdb {
    pub host: IpAddr,
    pub port: u16,
    pub namespace: String,
    pub secret: Option<String>,
}
