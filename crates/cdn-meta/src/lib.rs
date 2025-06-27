use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Hashes as used in the definitions.
pub type Hash = [u8; 32];
/// The type used to refer to a hash which is file metadata.
pub type FileMetaHash = Hash;

/// A blob of metadata, bincode encoded.
#[derive(Deserialize, Serialize)]
pub enum Metadata {
    /// The metadata represents a [`File`].
    File(File),
    /// The metadata represents a [`Directory`].
    Directory(Directory),
}

/// Metadata about a single file.
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
pub struct Block {
    pub shards: Vec<Location>,
    /// Offset in bytes this block is placed in the file.
    pub start_offset: u64,
    /// Offset in bytes the last byte in this block is placed in the file.
    pub end_offset: u64,
    /// Hash of the block data in plaintext,
    pub content_hash: Hash,
    /// Hash of the block data after it's encrypted, but before encoding.
    pub encrypted_hash: Hash,
}

/// Location information for shards in 0-DB
#[derive(Deserialize, Serialize)]
pub struct Location {
    /// 0-DB host IP address and port.
    pub host: SocketAddr,
    /// 0-DB namespace.
    pub namespace: String,
    /// 0-DB namespace secret, if one is present.
    pub secret: Option<String>,
}
