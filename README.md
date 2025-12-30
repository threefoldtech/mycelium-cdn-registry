# Mycelium CDN Registry

The Mycelium CDN Registry is a system for storing and retrieving **object metadata** in a distributed content delivery network.

This repo consists of three main components:

1. **`cdn-meta`**: A Rust library that defines the metadata format for objects
2. **`mycdnctl`**: A command-line tool for uploading objects to the CDN
3. **`registry`**: A service for storing and retrieving encrypted metadata blobs

## Storage Model (High Level)

- **File content** is split into chunks, encrypted, erasure-coded into shards, and stored in **Hero Redis** instances.
- **Metadata** (including shard locations) is encrypted and stored in the **Registry** service (PostgreSQL-backed).
- A **content URL** encodes:
  - the hash of the encrypted metadata (used as the registry key / subdomain)
  - the hash of the plaintext metadata (used as the decryption key, via `?key=`)

## System Architecture

```mermaid
graph TD
    Client[Client] -->|Upload file| mycdnctl[mycdnctl CLI]
    mycdnctl -->|Split & encrypt| Chunks[Encrypted Chunks]
    mycdnctl -->|Create metadata| Meta[Metadata]
    Chunks -->|Erasure coding| Shards[Shards]
    Shards -->|Store| HeroRedis[Hero Redis Instances]
    Meta -->|Encrypt| EncMeta[Encrypted Metadata]
    EncMeta -->|Store| Registry[Registry Service]
    Registry -->|Store in| PostgreSQL[(PostgreSQL)]

    User[End User] -->|Request content| CDN[Mycelium CDN]
    CDN -->|Fetch metadata| Registry
    CDN -->|Fetch shards| HeroRedis
```

## Hero Redis

Shard storage is performed via **Hero Redis**, a Redis-compatible server with an authentication flow based on:

- `CHALLENGE`
- `TOKEN <pubkey> <signature>`
- `AUTH <token>`
- `SELECT <db>`

`mycdnctl` can authenticate to Hero Redis using either:

- a **session token** (stored in config), or
- an **Ed25519 private key** (stored in config) to perform `CHALLENGE/TOKEN/AUTH` at runtime

## Using `mycdnctl`

`mycdnctl` uploads files and directories by:

1. Reading content
2. Splitting into chunks (default max: 5 MiB)
3. Encrypting each chunk with AES-128-GCM (key derived from chunk plaintext hash)
4. Reed-Solomon erasure coding each encrypted chunk into `n` shards
5. Writing one shard to each configured Hero Redis backend
6. Creating + encrypting metadata and uploading it to the registry
7. Printing a content URL

### Installation

Either download a release artifact, or build from source:

```bash
cd crates/mycdnctl
cargo build --release
```

### Configuration

Before using `mycdnctl`, create a configuration file (default: `config.toml`) specifying Hero Redis backends used for shard storage.

#### Config Format (`config.toml`)

- `required_shards`: the minimum number of shards needed to reconstruct a chunk
- `[[backends]]`: list of Hero Redis shard stores; **one shard is written to each backend**

Rules:

- `required_shards >= 1`
- `required_shards <= number of configured backends`

Example:

```toml
# Minimum shards required to recover (k)
required_shards = 3

# One shard is written to each backend (n = number of backends)
[[backends]]
kind = "hero_redis"
host = "10.0.0.10:6379"
db = 7

[[backends]]
kind = "hero_redis"
host = "10.0.0.11:6379"
db = 7

[[backends]]
kind = "hero_redis"
host = "10.0.0.12:6379"
db = 7

# Optional auth:
# 1) Session token (client uses `AUTH <token>`)
[[backends]]
kind = "hero_redis"
host = "10.0.0.13:6379"
db = 7
auth = { type = "token", token = "your-session-token" }

# 2) Ed25519 private key (client performs CHALLENGE/TOKEN/AUTH)
# Note: private_key must be 64 hex chars (32 bytes).
[[backends]]
kind = "hero_redis"
host = "10.0.0.14:6379"
db = 7
auth = { type = "private_key", private_key = "e5f6a7b8... (64 hex chars total)" }
```

### Uploading Files

To upload a file to the CDN:

```bash
mycdnctl upload --config config.toml path/to/file.txt
```

Optional parameters:

- `--mime`: Specify the MIME type (otherwise inferred)
- `--name`: Specify a custom name (otherwise uses filename)
- `--chunk-size`: Chunk size in bytes (default: 5 MiB, range: 1–5 MiB)
- `--include-password`: Include the Hero Redis **session token** (if configured) in the metadata (not recommended for public content)
- `--registry`: Specify registry URL (default: `https://cdn.mycelium.grid.tf`)

### Uploading Directories

To upload a directory (non-recursive) to the CDN:

```bash
mycdnctl upload --config config.toml path/to/directory
```

Each regular file inside the directory is uploaded as a file object, and then a directory metadata object referencing those files is uploaded.

### Understanding the Output

After uploading, `mycdnctl` prints a URL for accessing the object:

```text
Object <name> saved. Url: http://[encrypted-hash].[registry-domain]/?key=[plaintext-hash]
```

Where:

- `[encrypted-hash]` is the hex-encoded Blake3 hash of the **encrypted metadata blob** (used as registry key and subdomain)
- `[plaintext-hash]` is the hex-encoded Blake3 hash of the **plaintext metadata blob** (used as the decryption key)

## Security Notes

- Encryption keys are content-derived:
  - Chunk encryption key = Blake3 hash of the plaintext chunk
  - Metadata encryption key = Blake3 hash of the plaintext metadata blob
- `--include-password` embeds Hero Redis session tokens into metadata (if configured).
  - Anyone who can fetch the metadata can use the embedded token to access shard storage.
  - For public content, prefer configuring Hero Redis for unauthenticated reads and keep `--include-password` off.

## Development

This repository is a Cargo workspace-like layout (multiple crates under `crates/`):

- `crates/cdn-meta`
- `crates/mycdnctl`
- `crates/registry`

Build / test individual crates via their crate directories, or use `--manifest-path` from the repo root.