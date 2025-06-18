use axum::{Router, extract::Path, http::StatusCode, routing::get};
use tracing::{Level, debug};

/// Lenght of a hex encoded hash.
const HEX_HASH_LEN: usize = 64;
/// Binary size of a hash.
const HASH_LEN: usize = 32;

pub struct Server {}

/// Spawns the HTTP API listener on the given port
pub async fn http_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let api_router = Router::new().route("/metadata/{hash}", get(load_meta));

    let app = Router::new().nest("/api/v1", api_router);

    let listener = tokio::net::TcpListener::bind(format!("[::]:{port}")).await?;

    Ok(axum::serve(listener, app).await?)
}

/// Handler to load the metadata blob for a given hash. The data is returned as binary data.
#[tracing::instrument(level = Level::DEBUG)]
pub async fn load_meta(Path(path): Path<String>) -> Result<Vec<u8>, StatusCode> {
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

    // TODO: load data from postgres

    Ok(vec![0, 1, 2, 3, 4, 5, 6])
}
