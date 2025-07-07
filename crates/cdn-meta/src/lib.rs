use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Magic bytes prepended in front of the metadata.
pub const METADATA_MAGIC: [u8; 4] = *b"MCDN";

/// Version of the metadata format in use.
pub const VERSION: u8 = 1;

/// Hashes as used in the definitions.
pub type Hash = [u8; 32];
/// The type used to refer to a hash which is file metadata.
pub type FileMetaHash = Hash;

/// A blob of metadata, bincode encoded.
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub enum Metadata {
    /// The metadata represents a [`File`].
    File(File),
    /// The metadata represents a [`Directory`].
    Directory(Directory),
}

impl Metadata {
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

    pub fn from_binary(input: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        if input.len() < 5 {
            return Err("Input too short to be valid data".into());
        }
        if input[..4] != METADATA_MAGIC {
            return Err("Invalid input magic".into());
        }
        if input[4] != VERSION {
            return Err("Invalid metadata version".into());
        }

        let config = bincode::config::standard()
            .with_big_endian()
            .with_fixed_int_encoding();
        Ok(bincode::decode_from_slice(&input[5..], config)?)
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
    /// A list of file hashes. This also includes an optional hash in case the file metadata is
    /// encrypted. In this case, the first hash is the hash of the encrypted content (it's key in
    /// the registry), and the second hash is the hash of the unencrypted content, which is also
    /// the encryption key.
    pub files: Vec<(FileMetaHash, Option<Hash>)>,
    /// Name of the directory.
    pub name: String,
}

/// Info about distribution of a single block.
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub struct Block {
    /// Information needed to retrieve shards
    pub shards: Vec<Location>,
    /// The minimal amount of shards needed to decode the data
    pub required_shards: u16,
    /// Offset in bytes this block is placed in the file.
    pub start_offset: u64,
    /// Offset in bytes the last byte in this block is placed in the file.
    pub end_offset: u64,
    /// Hash of the block data in plaintext,
    pub content_hash: Hash,
    /// Hash of the block data after it's encrypted, but before encoding.
    pub encrypted_hash: Hash,
    /// The nonce used for encryption
    pub nonce: [u8; 12],
}

/// Location information for shards in 0-DB
#[derive(Clone, Deserialize, Serialize, bincode::Encode, bincode::Decode)]
pub struct Location {
    /// 0-DB host IP address and port.
    pub host: SocketAddr,
    /// 0-DB namespace.
    pub namespace: String,
    /// 0-DB namespace secret, if one is present.
    pub secret: Option<String>,
}
