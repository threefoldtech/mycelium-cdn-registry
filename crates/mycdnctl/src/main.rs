use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use aes_gcm::{KeyInit, aead::Aead};
use clap::{Parser, Subcommand};
use rand::random;
use rayon::prelude::*;
use reed_solomon_erasure::galois_8::ReedSolomon;
use reqwest::Url;

use crate::{config::Config, zdb::Zdb};

/// Module for config file
mod config;
/// Module to work with 0-DB
mod zdb;

/// The maximum unencrypted size of one chunk of content
const MAX_CHUNK_SIZE: u64 = 5 << 20; // 5 MiB
/// The default configuration file path
const DEFAULT_CONFIG_FILE: &str = "config.toml";

// TODO: Set to correct version
/// The default URL of the registry used to upload data.
const DEFAULT_MYCELIUM_CDN_REGISTRY: &str = "https://cdn.mycelium.io";

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
    #[arg( short, long, default_value = DEFAULT_MYCELIUM_CDN_REGISTRY)]
    registry: Url,
}

#[derive(Clone, Subcommand)]
/// Available commands to manage mycelium cdn objects.
enum Command {
    /// Upload an object (file or directory) to 0-db's and save the metadata in the mycelium cdn
    /// registry.
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
        #[arg(long, default_value_t = MAX_CHUNK_SIZE, value_parser = clap::value_parser!(u64).range(1<<20..=5<<20))]
        chunk_size: u64,
        #[arg(short, long, default_value = DEFAULT_CONFIG_FILE)]
        config: PathBuf,
        /// Whether to inlcude the passwords for the 0-db namespaces or not. If this is not the
        /// case, the 0-db namespaces must be PUBLIC for users to be able to download chunks. Note
        /// that setting this will essentially give everyone who can download the metadata access
        /// to your passwords.
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
            name,
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
            let config = toml::from_str(&toml_str)?;

            let metas = if ft.is_file() {
                upload_file(&object, mime, chunk_size, config, include_password)?
            } else {
                upload_dir(&object)?
            };

            let client = reqwest::blocking::Client::new();
            for meta in metas {
                let bin_meta = meta.to_binary()?;
                let hash = blake3::hash(&bin_meta);
                let part = reqwest::blocking::multipart::Part::bytes(bin_meta);
                let form = reqwest::blocking::multipart::Form::new().part("data", part);
                let mut url = args.registry.clone();
                url.set_path("/api/v1/metadata");
                client.post(url).multipart(form).send()?;

                println!("File {} saved. Hash: {hash}", object.display());
            }
        }
    }

    Ok(())
}

/// Encrypt, chunk, and upload the chunks
fn upload_file(
    file: &Path,
    mime: Option<String>,
    chunk_size: u64,
    config: Config,
    include_passwords: bool,
) -> Result<Vec<cdn_meta::Metadata>, Box<dyn std::error::Error>> {
    let Some(name) = file.file_name() else {
        return Err("File must have a non-empty name".into());
    };
    let Some(name) = name.to_str() else {
        return Err("File name must be valid UTF-8".into());
    };
    let mut file = File::open(file)?;
    let mut content = vec![];
    file.read_to_end(&mut content)?;

    let orig_hash = blake3::hash(&content);
    let mime = mime.or_else(|| infer::get(&content).map(|t| t.mime_type().into()));

    // TODO: Compress?

    // Chunk content to size. This must be done now since decryption can only happen at the
    // beginning, so decrypting a chunk created after encryption would require the whole encrypted
    // object regardless.
    let mut chunks = Vec::with_capacity(content.len().div_ceil(chunk_size as usize));
    for i in 0..chunks.capacity() {
        chunks.push(
            &content[i * chunk_size as usize..((i + 1) * chunk_size as usize).min(content.len())],
        );
    }

    let mut meta = cdn_meta::File {
        content_hash: *orig_hash.as_bytes(),
        name: name.to_string(),
        mime,
        blocks: Vec::with_capacity(chunks.len()),
    };

    for (chunk_idx, chunk) in chunks.into_iter().enumerate() {
        let chunk_plain_hash = blake3::hash(chunk);
        let encryptor = aes_gcm::Aes256Gcm::new((&chunk_plain_hash.as_bytes()[..]).into());
        // TODO: Save nonce
        let nonce: [u8; 12] = random();
        let mut ciphertext = encryptor
            .encrypt(&nonce.into(), chunk)
            .map_err(|_| "Encryption failed")?;
        let chunk_cipher_hash = blake3::hash(&ciphertext);

        // pkcs7 extend data
        let mut padding = ciphertext.len() % config.required_shards as usize;
        if padding == 0 {
            // FIXME: padding could be bigger than 255
            padding = config.required_shards as usize;
        }

        ciphertext.extend(std::iter::repeat_n(padding as u8, padding));

        // Now we can do encoding of the chunk into smaller chunks
        //TODO:
        let encoder = ReedSolomon::new(
            config.required_shards as usize,
            config.zdbs.len() - config.required_shards as usize,
        )?;

        // First construct placeholders
        // We already padded ciphetext so its length is a multiple of required_shards.
        let shard_size = ciphertext.len() / config.required_shards as usize;

        let mut shards: Vec<Vec<u8>> = ciphertext.chunks_exact(shard_size).map(Vec::from).collect();
        shards.extend(vec![
            vec![0; shard_size];
            config.zdbs.len() - config.required_shards as usize
        ]);

        encoder.encode(&mut shards)?;

        for (shard, zdb_config) in shards.iter().zip(&config.zdbs) {
            let mut zdb = Zdb::new(
                zdb_config.host,
                &zdb_config.namespace,
                zdb_config.secret.as_deref(),
            )?;

            zdb.set(&chunk_cipher_hash.as_bytes()[..], shard)?;
        }

        meta.blocks.push(cdn_meta::Block {
            shards: config
                .zdbs
                .iter()
                .map(|zdb| cdn_meta::Location {
                    host: zdb.host,
                    namespace: zdb.namespace.clone(),
                    secret: if include_passwords {
                        zdb.secret.clone()
                    } else {
                        None
                    },
                })
                .collect(),
            start_offset: chunk_idx as u64 * chunk_size,
            end_offset: ((chunk_idx + 1) as u64 * chunk_size) - 1,
            content_hash: *chunk_plain_hash.as_bytes(),
            encrypted_hash: *chunk_cipher_hash.as_bytes(),
        });
    }

    Ok(vec![cdn_meta::Metadata::File(meta)])
}

/// For every item in dir -> upload item, then create dir metadata
fn upload_dir(dir: &Path) -> Result<Vec<cdn_meta::Metadata>, Box<dyn std::error::Error>> {
    todo!()
}
