use std::{
    fs::FileType,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};

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
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Upload { object, mime, name } => {
            if !object.exists() {
                eprintln!("{} does not exist", object.display());
                std::process::exit(1);
            }

            let ft = object.metadata()?.file_type();
            if !(ft.is_dir() || ft.is_file()) {
                eprintln!("Object must be a regular file or a directory");
                std::process::exit(1);
            }

            let meta = if ft.is_file() {
                upload_file(&object)?
            } else {
                upload_dir(&object)?
            }

            todo!();
        }
    }
}

/// Encrypt, chunk, and upload the chunks
fn upload_file(file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    todo!();
}

/// For every item in dir -> upload item, then create dir metadata
fn upload_dir(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}
