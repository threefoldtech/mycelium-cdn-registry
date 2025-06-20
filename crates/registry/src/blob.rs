use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Blob {
    /// Hash op the blob data
    pub hash: [u8; 32],
    /// Actual blob data
    pub data: Vec<u8>,
    /// Size of the blob data
    pub size: u64,
    /// Creating time (i.e. upload time) of the blob
    pub created_at: DateTime<Utc>,
}
