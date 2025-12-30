use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Magic bytes prepended in front of the metadata blob.
pub const METADATA_MAGIC: [u8; 4] = *b"MCDN";

/// Version of the metadata format in use.
pub const VERSION: u8 = 1;

/// Hash type used throughout metadata definitions.
pub type Hash = [u8; 16];

/// The type used to refer to a hash which is file metadata.
pub type FileMetaHash = Hash;

/// A metadata blob, bincode encoded.
///
/// Encoding format:
/// - 4 bytes magic: [`METADATA_MAGIC`]
/// - 1 byte version: [`VERSION`]
/// - bincode payload (big-endian, fixed-int encoding)
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub enum Metadata {
    /// The metadata represents a [`File`].
    File(File),
    /// The metadata represents a [`Directory`].
    Directory(Directory),
}

impl Metadata {
    /// Encode metadata to the binary format.
    pub fn to_binary(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let config = bincode::config::standard()
            .with_big_endian()
            .with_fixed_int_encoding();

        let encoded = bincode::encode_to_vec(self, config)?;
        let mut out = Vec::with_capacity(encoded.len() + 5);
        out.extend(&METADATA_MAGIC);
        out.push(VERSION);
        out.extend(encoded);
        Ok(out)
    }

    /// Decode metadata from the binary format.
    ///
    /// Returns `(metadata, bytes_used)`.
    pub fn from_binary(input: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        if input.len() < 5 {
            return Err("Input too short to be valid metadata".into());
        }
        if input[..4] != METADATA_MAGIC {
            return Err("Invalid metadata magic".into());
        }
        if input[4] != VERSION {
            return Err("Invalid metadata version".into());
        }

        let config = bincode::config::standard()
            .with_big_endian()
            .with_fixed_int_encoding();

        let (m, used) = bincode::decode_from_slice(&input[5..], config)?;
        Ok((m, used + 5))
    }

    /// Get the name of the object.
    pub fn name(&self) -> String {
        match self {
            Metadata::File(file) => file.name.clone(),
            Metadata::Directory(dir) => dir.name.clone(),
        }
    }
}

/// Metadata about a single file.
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub struct File {
    /// The hash of the unencrypted file content. This is also used as encryption key.
    pub content_hash: Hash,
    /// Name of the file.
    pub name: String,
    /// Mime type of the file content.
    pub mime: Option<String>,
    /// The blocks which make up the actual data of the file.
    pub blocks: Vec<Block>,
}

/// Metadata about a single directory.
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub struct Directory {
    /// A list of file metadata hashes, optionally paired with a plaintext hash (when file metadata
    /// itself is encrypted). In that case:
    /// - first hash: hash of the encrypted file metadata (its key in the registry)
    /// - second hash: hash of the plaintext file metadata (also the decryption key)
    pub files: Vec<(FileMetaHash, Option<Hash>)>,
    /// Name of the directory.
    pub name: String,
}

/// Info about distribution of a single block.
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub struct Block {
    /// Information needed to retrieve shards for this block (Hero Redis only).
    pub shards: Vec<ShardLocation>,
    /// The minimal amount of shards needed to decode the data.
    pub required_shards: u16,
    /// Offset in bytes this block is placed in the file.
    pub start_offset: u64,
    /// Offset in bytes the last byte in this block is placed in the file.
    pub end_offset: u64,
    /// Hash of the block data in plaintext.
    pub content_hash: Hash,
    /// Hash of the block data after it's encrypted, but before encoding.
    pub encrypted_hash: Hash,
    /// The nonce used for encryption.
    pub nonce: [u8; 12],
}

/// Location information for shards stored in Hero Redis.
#[derive(Clone, Debug, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub struct ShardLocation {
    /// Hero Redis host IP address and port.
    pub host: SocketAddr,
    /// Database number to `SELECT` after authentication.
    pub db: u16,
    /// Optional authentication material.
    ///
    /// For public data this should generally be `None`.
    pub auth: Option<HeroRedisAuth>,
}

/// Authentication material for Hero Redis.
#[derive(Clone, Debug, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub enum HeroRedisAuth {
    /// Session token used with `AUTH <token>`.
    Token(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_metadata() {
        let meta = Metadata::File(File {
            content_hash: [1u8; 16],
            name: "test.bin".to_string(),
            mime: Some("application/octet-stream".to_string()),
            blocks: vec![Block {
                shards: vec![ShardLocation {
                    host: "127.0.0.1:6379".parse().unwrap(),
                    db: 7,
                    auth: None,
                }],
                required_shards: 1,
                start_offset: 0,
                end_offset: 3,
                content_hash: [2u8; 16],
                encrypted_hash: [3u8; 16],
                nonce: [4u8; 12],
            }],
        });

        let bin = meta.to_binary().unwrap();
        let (decoded, used) = Metadata::from_binary(&bin).unwrap();
        assert_eq!(used, bin.len());
        assert_eq!(decoded.name(), meta.name());
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bin = vec![0u8; 10];
        bin[..4].copy_from_slice(b"NOPE");
        bin[4] = VERSION;
        assert!(Metadata::from_binary(&bin).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bin = Vec::new();
        bin.extend(&METADATA_MAGIC);
        bin.push(VERSION + 1);
        bin.extend([0u8; 8]);
        assert!(Metadata::from_binary(&bin).is_err());
    }
}
