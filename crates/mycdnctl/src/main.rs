use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use aes_gcm::{KeyInit, aead::Aead};
use clap::{Parser, Subcommand};
use rand::random;
use reed_solomon_erasure::galois_8::ReedSolomon;
use reqwest::Url;

use crate::{
    config::{Config, HeroRedisAuth, ShardBackend},
    hero_redis::{ChallengeFormat, HeroRedis},
};

/// Module for config file
mod config;
/// Module to work with Hero Redis backend
mod hero_redis;

/// The maximum unencrypted size of one chunk of content
const MAX_CHUNK_SIZE: u64 = 5 << 20; // 5 MiB
/// The default configuration file path
const DEFAULT_CONFIG_FILE: &str = "config.toml";

/// The default URL of the registry used to upload data.
const DEFAULT_MYCELIUM_CDN_REGISTRY: &str = "https://cdn.mycelium.grid.tf";

/// Name, Encrypted binary metadata, hash of the encrypted content, and hash of the plaintext content
/// (which is the encryption key)
type MetaInfo = (String, Vec<u8>, [u8; 16], [u8; 16]);

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
    #[arg(short, long, default_value = DEFAULT_MYCELIUM_CDN_REGISTRY)]
    registry: Url,
}

#[derive(Clone, Subcommand)]
/// Available commands to manage mycelium cdn objects.
enum Command {
    /// Upload an object (file or directory) to Hero Redis shard backends and save the metadata in
    /// the mycelium cdn registry.
    Upload {
        /// The object to upload, this must be either a file or directory
        object: PathBuf,

        /// The mime type of the object. For directories, this is ignored. For files, if this is
        /// set, this value will be used, otherwise an attempt is made to infer the mime type from
        /// the filename/content.
        #[arg(short, long)]
        mime: Option<String>,

        /// Custom name of the object. If this is not set, the leaf of the path value is used.
        #[arg(short, long)]
        name: Option<String>,

        /// The size of chunks to generate when a file is uploaded which is larger than this
        /// object.
        #[arg(
            long,
            default_value_t = MAX_CHUNK_SIZE,
            value_parser = clap::value_parser!(u64).range(1<<20..=5<<20)
        )]
        chunk_size: u64,

        #[arg(short, long, default_value = DEFAULT_CONFIG_FILE)]
        config: PathBuf,

        /// Whether to include the Hero Redis session token in the metadata (if configured).
        ///
        /// If this is false, Hero Redis instances must be publicly readable for downloads to work.
        ///
        /// Note: embedding tokens in metadata can grant anyone who can download metadata access to
        /// the underlying stored shards.
        #[arg(long, default_value_t = false)]
        include_password: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Upload {
            object,
            mime,
            name: _,
            chunk_size,
            config,
            include_password,
        } => {
            if !object.exists() {
                eprintln!("{} does not exist", object.display());
                std::process::exit(1);
            }

            let ft = object.metadata()?.file_type();
            if !(ft.is_dir() || ft.is_file()) {
                eprintln!("Object must be a regular file or a directory");
                std::process::exit(1);
            }

            if !config.exists() {
                eprintln!("Config file does not exist");
                std::process::exit(1);
            }
            let mut config_file = File::open(config)?;
            let mut toml_str = String::new();
            config_file.read_to_string(&mut toml_str)?;
            let config: Config = toml::from_str(&toml_str)?;

            if let Err(msg) = config.validate_for_upload() {
                eprintln!("Invalid config: {msg}");
                std::process::exit(1);
            }

            let metas = if ft.is_file() {
                upload_file(&object, mime, chunk_size, &config, include_password)?
            } else {
                upload_dir(&object, chunk_size, &config, include_password)?
            };

            let client = reqwest::blocking::Client::new();
            for (name, encrypted_blob, encrypted_hash, plaintext_hash) in metas {
                let part = reqwest::blocking::multipart::Part::bytes(encrypted_blob);
                let form = reqwest::blocking::multipart::Form::new().part("data", part);
                let mut url = args.registry.clone();
                url.set_path("/api/v1/metadata");
                client.post(url.clone()).multipart(form).send()?;

                url.set_query(Some(&format!(
                    "key={}",
                    faster_hex::hex_string(&plaintext_hash)
                )));

                let host = format!(
                    "{}.{}",
                    faster_hex::hex_string(&encrypted_hash),
                    url.host_str().expect("Registry URL has a host")
                );
                url.set_host(Some(&host))?;

                url.set_path("/");
                url.set_scheme("http")
                    .map_err(|_| "Could not set scheme to http")?;

                println!("Object {name} saved. Url: {url}");
            }
        }
    }

    Ok(())
}

/// Encrypt, chunk, and upload the chunks/shards (Hero Redis only).
fn upload_file(
    file_path: &Path,
    mime: Option<String>,
    chunk_size: u64,
    config: &Config,
    include_secrets_in_meta: bool,
) -> Result<Vec<MetaInfo>, Box<dyn std::error::Error>> {
    let Some(name) = file_path.file_name() else {
        return Err("File must have a non-empty name".into());
    };
    let Some(name) = name.to_str() else {
        return Err("File name must be valid UTF-8".into());
    };

    let mut file = File::open(file_path)?;
    let mut content = vec![];
    file.read_to_end(&mut content)?;

    let orig_hash = blake3_16_hash(&content);
    let mime = mime
        .or_else(|| infer::get(&content).map(|t| t.mime_type().into()))
        .unwrap_or_else(|| {
            mime_guess::from_path(file_path)
                .first_or_octet_stream()
                .to_string()
        });

    let backends = config.shard_backends();
    let n = backends.len();
    let k = config.required_shards as usize;

    let mut chunks = Vec::with_capacity(content.len().div_ceil(chunk_size as usize));
    for i in 0..chunks.capacity() {
        chunks.push(
            &content[i * chunk_size as usize..((i + 1) * chunk_size as usize).min(content.len())],
        );
    }

    let mut meta = cdn_meta::File {
        content_hash: orig_hash,
        name: name.to_string(),
        mime: Some(mime),
        blocks: Vec::with_capacity(chunks.len()),
    };

    for (chunk_idx, chunk) in chunks.into_iter().enumerate() {
        // Per-chunk encryption key: hash of plaintext chunk
        let chunk_plain_hash = blake3_16_hash(chunk);
        let encryptor = aes_gcm::Aes128Gcm::new((&chunk_plain_hash[..]).into());
        let nonce: [u8; 12] = random();
        let mut ciphertext = encryptor
            .encrypt(&nonce.into(), chunk)
            .map_err(|_| "Encryption failed")?;

        // Key used for storage: hash of encrypted (unpadded) chunk
        let chunk_cipher_hash = blake3_16_hash(&ciphertext);

        // PKCS#7-like padding so ciphertext length is a multiple of k (required_shards).
        // Padding bytes are value == padding length.
        let rem = ciphertext.len() % k;
        let pad_len = if rem == 0 { k } else { k - rem };
        if pad_len > 255 {
            return Err(format!(
                "padding length {pad_len} exceeds 255 (required_shards={k}); reduce required_shards"
            )
            .into());
        }
        ciphertext.extend(std::iter::repeat_n(pad_len as u8, pad_len));

        // Reed-Solomon encode into n shards total, with k data shards.
        let encoder = ReedSolomon::new(k, n - k)?;

        let shard_size = ciphertext.len() / k;
        let mut shards: Vec<Vec<u8>> = ciphertext.chunks_exact(shard_size).map(Vec::from).collect();
        shards.extend(vec![vec![0; shard_size]; n - k]);

        encoder.encode(&mut shards)?;

        // Store each shard in the corresponding backend.
        for (shard, backend) in shards.iter().zip(backends.iter()) {
            store_shard(backend, &chunk_cipher_hash[..], shard)?;
        }

        // Build metadata shard locations (optionally stripping auth tokens).
        let locations = backends
            .iter()
            .map(|b| shard_location_for_meta(b, include_secrets_in_meta))
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

        meta.blocks.push(cdn_meta::Block {
            shards: locations,
            required_shards: config.required_shards,
            start_offset: chunk_idx as u64 * chunk_size,
            end_offset: ((chunk_idx + 1) as u64 * chunk_size) - 1,
            content_hash: chunk_plain_hash,
            encrypted_hash: chunk_cipher_hash,
            nonce,
        });
    }

    Ok(vec![encrypt_meta(&cdn_meta::Metadata::File(meta))?])
}

/// For every item in dir -> upload item, then create dir metadata
fn upload_dir(
    dir: &Path,
    chunk_size: u64,
    config: &Config,
    include_secrets_in_meta: bool,
) -> Result<Vec<MetaInfo>, Box<dyn std::error::Error>> {
    if !dir.exists() || !dir.is_dir() {
        return Err(format!("{} must be a path to an existing directory", dir.display()).into());
    }

    let Some(name) = dir.file_name() else {
        return Err("Directory name can't be empty".into());
    };

    let Some(name) = name.to_str() else {
        return Err("File name must be valid UTF-8".into());
    };

    let mut meta = cdn_meta::Directory {
        files: vec![],
        name: name.to_string(),
    };

    let mut metas = vec![];

    for file in std::fs::read_dir(dir)? {
        let file = file?;

        if file.file_type()?.is_file() {
            eprintln!("Upload {}", file.path().display());
            let mi = upload_file(
                &file.path(),
                None,
                chunk_size,
                config,
                include_secrets_in_meta,
            )?;
            metas.extend(mi.iter().cloned());
            meta.files
                .extend(mi.into_iter().map(|(_, _, eh, ph)| (eh, Some(ph))));
        } else {
            eprintln!(
                "Directory item at {} is not a regular file",
                file.path().display()
            );
        }
    }

    metas.push(encrypt_meta(&cdn_meta::Metadata::Directory(meta))?);
    Ok(metas)
}

fn store_shard(
    backend: &ShardBackend,
    key: &[u8],
    shard: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let ShardBackend::HeroRedis { host, db, auth } = backend;

    let client = HeroRedis::connect(*host).map_err(|e| format!("Hero Redis connect: {e}"))?;

    let mut client = match auth {
        None => {
            let mut c = client;
            c.select(*db)
                .map_err(|e| format!("Hero Redis SELECT {db}: {e}"))?;
            c
        }
        Some(HeroRedisAuth::Token { token }) => client
            .login_with_token(token, Some(*db))
            .map_err(|e| format!("Hero Redis token login: {e}"))?,
        Some(HeroRedisAuth::PrivateKey { private_key }) => {
            let (c, _token) = client
                .login_with_private_key_hex(
                    private_key,
                    ChallengeFormat::HexDecodedBytes,
                    Some(*db),
                )
                .map_err(|e| format!("Hero Redis private-key login: {e}"))?;
            c
        }
    };

    client
        .set(key, shard)
        .map_err(|e| format!("Hero Redis SET failed: {e}"))?;

    Ok(())
}

fn shard_location_for_meta(
    backend: &ShardBackend,
    include_secrets: bool,
) -> Result<cdn_meta::ShardLocation, Box<dyn std::error::Error>> {
    let ShardBackend::HeroRedis { host, db, auth } = backend;

    let auth = if !include_secrets {
        None
    } else {
        match auth {
            None => None,
            Some(HeroRedisAuth::Token { token }) => {
                Some(cdn_meta::HeroRedisAuth::Token(token.clone()))
            }
            // Never embed private keys in metadata, even if include_secrets=true.
            Some(HeroRedisAuth::PrivateKey { .. }) => None,
        }
    };

    Ok(cdn_meta::ShardLocation {
        host: *host,
        db: *db,
        auth,
    })
}

/// Encrypts the binary blob of some metadata and returns the encrypted blob, the hash of the
/// encrypted data (which is the key it will be stored under), and the hash of the plaintext blob
/// (which is used as encryption key).
fn encrypt_meta(meta: &cdn_meta::Metadata) -> Result<MetaInfo, Box<dyn std::error::Error>> {
    let content_blob = meta.to_binary()?;
    let content_hash = blake3_16_hash(&content_blob);

    let encryptor = aes_gcm::Aes128Gcm::new((&content_hash[..]).into());
    let nonce: [u8; 12] = random();
    let mut ciphertext = encryptor
        .encrypt(&nonce.into(), content_blob.as_slice())
        .map_err(|_| "Encryption failed")?;

    // Append nonce to ciphertext for metadata decryption.
    ciphertext.extend(&nonce);

    let cipher_hash = blake3_16_hash(&ciphertext);

    Ok((meta.name(), ciphertext, cipher_hash, content_hash))
}

/// Hash an input to 16 bytes of output using blake3
fn blake3_16_hash(input: &[u8]) -> cdn_meta::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(input);
    let mut output = [0; 16];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    output
}
