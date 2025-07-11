use axum::{
    Router,
    extract::{Multipart, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use tracing::{Level, debug, error};

use crate::postgres::DB;

mod blob;
pub mod postgres;

/// Lenght of a hex encoded hash.
const HEX_HASH_LEN: usize = 32;
/// Binary size of a hash.
const HASH_LEN: usize = 16;

pub struct Server {}

/// Shared application state
#[derive(Clone)]
struct AppState {
    db: DB,
}

/// Spawns the HTTP API listener on the given port and with the given database connection.
pub async fn http_listener(port: u16, db: DB) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState { db };

    let api_router = Router::new()
        .route("/metadata/{hash}", get(load_meta))
        .route("/metadata", post(save_meta));

    let app = Router::new().nest("/api/v1", api_router).with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("[::]:{port}")).await?;

    Ok(axum::serve(listener, app).await?)
}

/// Handler to load the metadata blob for a given hash. The data is returned as binary data.
#[tracing::instrument(skip_all, level = Level::DEBUG)]
async fn load_meta(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> Result<Vec<u8>, StatusCode> {
    debug!("Validate input path");
    if path.len() != HEX_HASH_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    debug!("Decode input hash");
    let mut hash = [0u8; HASH_LEN];
    if faster_hex::hex_decode(path.as_bytes(), &mut hash).is_err() {
        debug!("Invalid character in content hash input");
        return Err(StatusCode::BAD_REQUEST);
    }

    let blob = state.db.load_blob(hash).await.map_err(|error| {
        error!(error, "Could not load blob");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some(blob) = blob {
        Ok(blob)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Handler to save a new binary data blob.
#[tracing::instrument(skip_all, level = Level::DEBUG)]
async fn save_meta(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(), StatusCode> {
    let content = if let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        if let Some(key) = field.name() {
            if key == "data" {
                field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    let key = blake3_16_hash(&content);

    state.db.store_blob(&key, &content).await.map_err(|err| {
        error!(err, "Failed to store blob content");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(())
}

/// Hash an input to 16 bytes of output using blake3
fn blake3_16_hash(input: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(input);
    let mut output = [0; 16];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    output
}
