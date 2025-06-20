use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use tracing::{Level, debug, error};

use crate::postgres::DB;

mod blob;
pub mod postgres;

/// Lenght of a hex encoded hash.
const HEX_HASH_LEN: usize = 64;
/// Binary size of a hash.
const HASH_LEN: usize = 32;

pub struct Server {}

/// Shared application state
#[derive(Clone)]
struct AppState {
    db: DB,
}

/// Spawns the HTTP API listener on the given port and with the given database connection.
pub async fn http_listener(port: u16, db: DB) -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState { db };

    let api_router = Router::new().route("/metadata/{hash}", get(load_meta));

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
