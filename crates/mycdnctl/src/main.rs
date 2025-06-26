use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use aes_gcm::{KeyInit, aead::Aead};
use clap::{Parser, Subcommand};
use rand::random;
use reed_solomon_erasure::galois_16::ReedSolomon;

use crate::config::Config;

/// Module for config file
mod config;
/// Module to work with 0-DB
mod zdb;

/// The maximum unencrypted size of one chunk of content
const MAX_CHUNK_SIZE: u64 = 5 << 20; // 5 MiB
/// The default configuration file path
const DEFAULT_CONFIG_FILE: &str = "config.toml";

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
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
        #[arg(long, default_value_t = MAX_CHUNK_SIZE, value_parser = clap::value_parser!(u64).range(1<<20..5<<20))]
        chunk_size: u64,
        #[arg(short, long, default_value = DEFAULT_CONFIG_FILE)]
        config: PathBuf,
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

            let mut config_file = File::open(config)?;
            let mut toml_str = String::new();
            config_file.read_to_string(&mut toml_str)?;
            let config = toml::from_str(&toml_str)?;

            let meta = if ft.is_file() {
                upload_file(&object, chunk_size, config)?
            } else {
                upload_dir(&object)?
            };

            todo!();
        }
    }
}

/// Encrypt, chunk, and upload the chunks
fn upload_file(
    file: &Path,
    chunk_size: u64,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(file)?;
    let mut content = vec![];
    file.read_to_end(&mut content)?;

    let orig_hash = blake3::hash(&content);

    // TODO: Compress?

    // Chunk content to size. This must be done now since decryption can only happen at the
    // beginning, so decrypting a chunk created after encryption would require the whole encrypted
    // object regardless.
    let mut chunks = Vec::with_capacity(content.len().div_ceil(chunk_size as usize));
    for i in 0..chunks.capacity() {
        chunks.push(&content[i * chunk_size as usize..(i + 1) * chunk_size as usize]);
    }

    for chunk in chunks {
        let encryptor = aes_gcm::Aes256Gcm::new((&orig_hash.as_bytes()[..]).into());
        let nonce: [u8; 12] = random();
        let mut ciphertext = encryptor
            .encrypt(&nonce.into(), chunk)
            .map_err(|_| "Encryption failed")?;

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
        let mut shards: Vec<Vec<u8>> = vec![Vec::new(); config.zdbs.len()];

        // We already padded ciphetext so its length is a multiple of required_shards.
        let shard_size = ciphertext.len() / config.required_shards as usize;

        for i in 0..config.required_shards as usize {
            shards[i] = ciphertext[i * shard_size..(i + 1) * shard_size].to_vec();
        }

        encoder.encode(&mut shards)?;
    }

    // TODO: upload encryped chunks

    todo!();
}

/// For every item in dir -> upload item, then create dir metadata
fn upload_dir(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}
