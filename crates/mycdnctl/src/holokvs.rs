use std::{
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// Client for storing/retrieving metadata blobs via the HoloKVS (Holochain) authorized key-value store.
///
/// This module intentionally does **not** depend on the Holochain client libraries directly.
/// Instead, it shells out to the `holokvs` CLI shipped with the HoloPoc directory in this repo.
/// That CLI already implements:
/// - connecting to the conductor (admin + app websocket)
/// - issuing app auth tokens
/// - authorizing signing credentials
/// - nonce fetching and canonical signing (VXEdDSA) for writes/deletes
///
/// This keeps `mycdnctl` lightweight and avoids re-implementing (and keeping in sync) the
/// exact signing/canonical-encoding rules required by the zome.
///
/// Storage model:
/// - key: hex string (lowercase) derived from the *encrypted metadata hash*
/// - value: hex string (lowercase) encoding of the encrypted metadata bytes (nonce already appended)
///
/// Notes:
/// - Writes require an X25519 private key (32 bytes as hex string, 64 hex chars; optional `0x` prefix).
/// - Reads do not require a key (per the CLI's `get` command).
#[derive(Debug, Clone)]
pub struct HoloKvsClient {
    cfg: HoloKvsConfig,
}

#[derive(Debug, Clone)]
pub struct HoloKvsConfig {
    /// Path to the `holokvs` CLI binary (default: `holokvs` in PATH).
    pub holokvs_path: PathBuf,

    /// Websocket host for admin/app interfaces (default in holokvs CLI: 127.0.0.1).
    pub host: String,

    /// Admin websocket port (holokvs CLI default: 8888).
    pub admin_port: u16,

    /// Optional app websocket port; if not set, holokvs will obtain/attach from admin.
    pub app_port: Option<u16>,

    /// Installed app id (holokvs CLI default: kv_store).
    pub app_id: String,

    /// Optional key prefix for namespacing in the global HoloKVS keyspace.
    ///
    /// Example: "mycelium-cdn/meta/".
    pub key_prefix: Option<String>,

    /// X25519 private key (hex) used for signed writes/deletes.
    /// This is required for `put_metadata` (writes).
    pub x25519_sk_hex: Option<String>,
}

impl Default for HoloKvsConfig {
    fn default() -> Self {
        Self {
            holokvs_path: PathBuf::from("holokvs"),
            host: "127.0.0.1".to_string(),
            admin_port: 8888,
            app_port: None,
            app_id: "kv_store".to_string(),
            key_prefix: None,
            x25519_sk_hex: None,
        }
    }
}

#[derive(Debug)]
pub enum HoloKvsError {
    MissingX25519SecretKey,
    InvalidHexKey(String),
    Io(std::io::Error),
    Utf8(std::string::FromUtf8Error),
    CommandFailed {
        cmd: String,
        status: Option<i32>,
        stdout: String,
        stderr: String,
    },
    ValueDecode(String),
}

impl fmt::Display for HoloKvsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HoloKvsError::MissingX25519SecretKey => write!(
                f,
                "missing x25519 secret key (configure `x25519_sk_hex` to enable writes)"
            ),
            HoloKvsError::InvalidHexKey(msg) => write!(f, "invalid hex key: {msg}"),
            HoloKvsError::Io(e) => write!(f, "io error: {e}"),
            HoloKvsError::Utf8(e) => write!(f, "utf8 error: {e}"),
            HoloKvsError::CommandFailed {
                cmd,
                status,
                stdout,
                stderr,
            } => write!(
                f,
                "holokvs command failed: {cmd} (status={:?})\nstdout: {stdout}\nstderr: {stderr}",
                status
            ),
            HoloKvsError::ValueDecode(msg) => write!(f, "failed to decode stored value: {msg}"),
        }
    }
}

impl std::error::Error for HoloKvsError {}

impl From<std::io::Error> for HoloKvsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<std::string::FromUtf8Error> for HoloKvsError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::Utf8(value)
    }
}

impl HoloKvsClient {
    pub fn new(cfg: HoloKvsConfig) -> Self {
        Self { cfg }
    }

    pub fn cfg(&self) -> &HoloKvsConfig {
        &self.cfg
    }

    /// Convert a 16-byte encrypted metadata hash into the HoloKVS key string.
    ///
    /// This key is stable and content-addressed, matching the registry-style behavior.
    /// If `cfg.key_prefix` is set, it is prepended to the key.
    pub fn metadata_key(&self, encrypted_hash: &[u8; 16]) -> String {
        let suffix = faster_hex::hex_string(encrypted_hash);
        match self.cfg.key_prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => format!("{prefix}{suffix}"),
            _ => suffix,
        }
    }

    /// Store (upsert) an encrypted metadata blob under its encrypted-hash key.
    ///
    /// This calls:
    /// - `holokvs set <key> <value_hex> --x25519-sk <sk>`
    pub fn put_metadata(
        &self,
        encrypted_hash: &[u8; 16],
        encrypted_metadata: &[u8],
    ) -> Result<(), HoloKvsError> {
        let sk = self
            .cfg
            .x25519_sk_hex
            .as_deref()
            .ok_or(HoloKvsError::MissingX25519SecretKey)?;

        // Basic validation early (helps avoid confusing conductor/zome errors).
        validate_x25519_sk_hex(sk)?;

        let key = self.metadata_key(encrypted_hash);

        // Idempotency: if the key already exists with the exact same bytes, skip the write.
        //
        // This is intentionally best-effort:
        // - If we can't read (e.g. conductor temporarily unavailable), we still attempt to write.
        // - If the stored value can't be decoded, we still attempt to write (repair path).
        if let Ok(Some(existing)) = self.get_metadata(encrypted_hash) {
            if existing == encrypted_metadata {
                return Ok(());
            }
        }

        let value_text = faster_hex::hex_string(encrypted_metadata);

        let mut args = Vec::<String>::new();
        args.push("set".to_string());
        args.push(key);
        args.push(value_text);
        args.push("--x25519-sk".to_string());
        args.push(sk.to_string());

        let out = self.run_holokvs(&args)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(self.command_failed("holokvs set", out))
        }
    }

    /// Retrieve the encrypted metadata blob for the given encrypted-hash key.
    ///
    /// This calls:
    /// - `holokvs get <key>`
    ///
    /// Returns `Ok(None)` if the key doesn't exist.
    pub fn get_metadata(&self, encrypted_hash: &[u8; 16]) -> Result<Option<Vec<u8>>, HoloKvsError> {
        let key = self.metadata_key(encrypted_hash);

        let mut args = Vec::<String>::new();
        args.push("get".to_string());
        args.push(key);

        let out = self.run_holokvs(&args)?;

        if out.status.success() {
            let stdout = String::from_utf8(out.stdout)?;
            let trimmed = stdout.trim();

            if trimmed.is_empty() {
                return Err(HoloKvsError::ValueDecode(
                    "empty value returned by holokvs".to_string(),
                ));
            }

            let bytes =
                hex_decode(trimmed).map_err(|e| HoloKvsError::ValueDecode(format!("{e}")))?;
            return Ok(Some(bytes));
        }

        // Heuristic: holokvs prints "Key '<k>' not found" and exits non-zero.
        let stderr = String::from_utf8(out.stderr.clone())?;
        let stderr_lc = stderr.to_lowercase();
        if stderr_lc.contains("not found") || stderr_lc.contains("does not exist") {
            return Ok(None);
        }

        Err(self.command_failed("holokvs get", out))
    }

    /// Delete the metadata blob (tombstone) for the given key.
    ///
    /// This calls:
    /// - `holokvs delete <key> --x25519-sk <sk>`
    ///
    /// Returns `Ok(true)` if it existed and was deleted; `Ok(false)` if it did not exist.
    pub fn delete_metadata(&self, encrypted_hash: &[u8; 16]) -> Result<bool, HoloKvsError> {
        let sk = self
            .cfg
            .x25519_sk_hex
            .as_deref()
            .ok_or(HoloKvsError::MissingX25519SecretKey)?;

        validate_x25519_sk_hex(sk)?;

        let key = self.metadata_key(encrypted_hash);

        let mut args = Vec::<String>::new();
        args.push("delete".to_string());
        args.push(key);
        args.push("--x25519-sk".to_string());
        args.push(sk.to_string());

        let out = self.run_holokvs(&args)?;
        if out.status.success() {
            Ok(true)
        } else {
            let stderr = String::from_utf8(out.stderr.clone())?;
            let stderr_lc = stderr.to_lowercase();
            if stderr_lc.contains("not found") || stderr_lc.contains("nothing deleted") {
                return Ok(false);
            }

            Err(self.command_failed("holokvs delete", out))
        }
    }

    fn run_holokvs(&self, args: &[String]) -> Result<Output, HoloKvsError> {
        let mut cmd = Command::new(&self.cfg.holokvs_path);

        // Global CLI args
        cmd.arg("--host").arg(&self.cfg.host);
        cmd.arg("--admin-port").arg(self.cfg.admin_port.to_string());

        if let Some(app_port) = self.cfg.app_port {
            cmd.arg("--app-port").arg(app_port.to_string());
        }

        cmd.arg("--app-id").arg(&self.cfg.app_id);

        // Subcommand + sub-args
        for a in args {
            cmd.arg(a);
        }

        Ok(cmd.output()?)
    }

    fn command_failed(&self, label: &str, out: Output) -> HoloKvsError {
        let cmd = format!(
            "{label} (bin={})",
            self.cfg
                .holokvs_path
                .as_os_str()
                .to_string_lossy()
                .to_string()
        );
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        HoloKvsError::CommandFailed {
            cmd,
            status: out.status.code(),
            stdout,
            stderr,
        }
    }
}

/// Validate that the provided x25519 secret key hex decodes into exactly 32 bytes.
fn validate_x25519_sk_hex(s: &str) -> Result<(), HoloKvsError> {
    let mut s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        s = rest;
    }

    if s.len() % 2 != 0 {
        return Err(HoloKvsError::InvalidHexKey(
            "hex string must have even length".to_string(),
        ));
    }

    if s.len() != 64 {
        return Err(HoloKvsError::InvalidHexKey(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            s.len() / 2
        )));
    }

    let mut out = [0u8; 32];
    faster_hex::hex_decode(s.as_bytes(), &mut out)
        .map_err(|_| HoloKvsError::InvalidHexKey("invalid hex string".to_string()))?;

    Ok(())
}

/// Decode a hex string (with optional 0x prefix) into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        s = rest;
    }
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }

    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|_| "invalid hex string".to_string())?;
    Ok(out)
}

// NOTE: Encrypted metadata values stored in HoloKVS are hex-encoded/decoded.
// (Previous configurable encoding support has been removed.)

/// Utility to check whether a configured holokvs binary exists.
///
/// This does not guarantee it is runnable, but is useful for preflight checks.
pub fn holokvs_binary_exists(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    if path.is_absolute() {
        return path.exists();
    }

    // If it's not absolute, defer to PATH lookup behavior by just checking it's a plausible file name.
    // The actual execution is handled by `Command`.
    path.file_name().and_then(OsStr::to_str).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 2, 0x10, 0xaa, 0xff];
        let enc = faster_hex::hex_string(&bytes);
        let dec = hex_decode(&enc).unwrap();
        assert_eq!(dec, bytes);
    }
}
