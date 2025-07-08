use std::net::SocketAddr;

use sha1::{Digest, Sha1};

/// Represents a connection to a 0-db.
pub struct Zdb {
    con: redis::Connection,
}

impl Zdb {
    /// Create a new 0-db and connect to it. This connects to the provided namespace and
    /// authenticates using the provided secret, if needed.
    pub fn new(
        host: SocketAddr,
        namespace: &str,
        secret: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client = redis::Client::open(format!("redis://{host}"))?;

        let mut con = client.get_connection()?;
        let secure_secret: Option<[u8; 20]> = if let Some(secret) = secret {
            let mut challenge = redis::cmd("AUTH")
                .arg("SECURE")
                .arg("CHALLENGE")
                .query::<String>(&mut con)?;
            // ":" -> ASCII/UTF-8 value 58
            challenge.push(':');
            challenge.push_str(secret);
            let mut hasher = Sha1::new();
            hasher.update(challenge);
            Some(hasher.finalize().into())
        } else {
            None
        };

        let mut ns_cmd = redis::cmd("SELECT");
        ns_cmd.arg(namespace);
        if let Some(ss) = secure_secret {
            ns_cmd.arg("SECURE").arg(faster_hex::hex_string(&ss));
        }
        ns_cmd.query::<()>(&mut con)?;

        Ok(Zdb { con })
    }

    /// Set a value associated with a key
    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        Ok(redis::cmd("SET").arg(key).arg(value).query(&mut self.con)?)
    }
}
