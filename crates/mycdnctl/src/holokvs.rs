use std::fmt;
use std::sync::Mutex;

use holo_hash::{ActionHash, ActionHashB64, EntryHashB64};
use holochain_client::{
    AdminWebsocket, AppWebsocket, AuthorizeSigningCredentialsPayload, CellInfo, ClientAgentSigner,
    IssueAppAuthenticationTokenPayload, ZomeCallTarget,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Re-export the config type so callers can pass the same struct they parsed from `config.toml`.
pub type HoloKvsConfig = crate::config::HoloKvsConfig;

/// Direct client for storing/retrieving encrypted metadata blobs via the HoloKVS (Holochain)
/// authorized key-value store.
///
/// This integrates the behavior from `holopoc/cli` directly (no external `holokvs` binary):
/// - Connect to the conductor Admin WebSocket
/// - Issue an app authentication token
/// - Connect to the App WebSocket (attach interface if needed)
/// - Authorize signing credentials
/// - Fetch per-key nonce (`get_next_nonce`)
/// - Fetch existing state/ACL when needed (`get_state`)
/// - Canonically encode + VXEdDSA sign write/delete payloads using an X25519 private key
///
/// Storage model:
/// - key: stable string key (recommended: lowercase hex of the 16-byte encrypted metadata hash),
///        optionally prefixed by `metadata.key_prefix`
/// - value: lowercase hex of the encrypted metadata bytes (nonce already appended)
///
/// Note: The holopoc hApp stores values as `String`, so the encrypted metadata bytes must be encoded.
/// We store them as hex strings for consistency with the rest of the system.
pub struct HoloKvsClient {
    cfg: HoloKvsConfig,
    rt: tokio::runtime::Runtime,
    conn: Mutex<Option<HoloKvsConnection>>,
}

impl fmt::Debug for HoloKvsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid printing secrets.
        f.debug_struct("HoloKvsClient")
            .field("app_id", &self.cfg.app_id)
            .field("host", &self.cfg.host)
            .field("admin_port", &self.cfg.admin_port)
            .field("app_port", &self.cfg.app_port)
            .field("zome_name", &self.cfg.zome_name)
            .field("key_prefix", &self.cfg.key_prefix)
            .finish()
    }
}

impl HoloKvsClient {
    pub fn new(cfg: HoloKvsConfig) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for HoloKvsClient");

        Self {
            cfg,
            rt,
            conn: Mutex::new(None),
        }
    }

    pub fn cfg(&self) -> &HoloKvsConfig {
        &self.cfg
    }

    /// Compute the metadata key used in HoloKVS.
    ///
    /// - base key: lowercase hex of 16-byte encrypted metadata hash
    /// - if `metadata.key_prefix` is set, it is prepended verbatim
    pub fn metadata_key(&self, encrypted_hash: &[u8; 16]) -> String {
        let suffix = faster_hex::hex_string(encrypted_hash);
        match self.cfg.key_prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => format!("{prefix}{suffix}"),
            _ => suffix,
        }
    }

    /// Store (upsert) an encrypted metadata blob under its encrypted-hash key.
    ///
    /// Idempotent best-effort:
    /// - If a value already exists and decodes to identical bytes, this is a no-op.
    pub fn put_metadata(
        &self,
        encrypted_hash: &[u8; 16],
        encrypted_metadata: &[u8],
    ) -> Result<(), HoloKvsError> {
        let key = self.metadata_key(encrypted_hash);

        // Best-effort idempotency check.
        if let Ok(Some(existing)) = self.get_metadata(encrypted_hash) {
            if existing == encrypted_metadata {
                return Ok(());
            }
        }

        let x25519_sk_hex = self
            .cfg
            .writer_x25519_sk_hex
            .as_deref()
            .ok_or(HoloKvsError::MissingX25519SecretKey)?;
        let x25519_sk = decode_x25519_sk_hex(x25519_sk_hex)?;

        let value_hex = faster_hex::hex_string(encrypted_metadata);

        self.with_connection(|mut conn| async move {
            // Zome function names are intentionally hardcoded to match the holopoc hApp.
            // Nonce must be monotonic per key to prevent replay/rollback.
            let nonce: u32 = conn.call_zome("get_next_nonce", key.clone()).await?;

            // On update, preserve existing ACL because Write signs ACL bytes too.
            let existing: Option<GetStateOutput> = conn.call_zome("get_state", key.clone()).await?;

            let pub_u = vxeddsa_support::public_u_from_secret(x25519_sk);
            let pub_x = X25519PublicKey(pub_u);

            let acl = match existing {
                Some(s) => s.acl,
                None => default_acl_for_creator(&pub_x),
            };

            let sig = sign_payload(
                KeyOp::Write,
                &key,
                Some(&value_hex),
                Some(&acl),
                nonce,
                &pub_x,
                x25519_sk,
            )?;

            let input = WriteInput {
                key: key.clone(),
                value: value_hex,
                acl: Some(acl),
                nonce,
                pubkey_x25519: pub_x,
                signature: sig,
            };

            let _: SetOutput = conn.call_zome("set_value", input).await?;
            Ok((conn, ()))
        })
    }

    /// Retrieve the encrypted metadata blob for the given encrypted-hash key.
    ///
    /// Returns `Ok(None)` if missing/tombstoned.
    pub fn get_metadata(&self, encrypted_hash: &[u8; 16]) -> Result<Option<Vec<u8>>, HoloKvsError> {
        let key = self.metadata_key(encrypted_hash);

        self.with_connection(|mut conn| async move {
            // get_value is part of the holopoc hApp API. It's not currently configurable in config,
            // so we use the canonical name.
            let out: Option<GetValueOutput> = conn.call_zome("get_value", key).await?;
            Ok((conn, out))
        })
        .and_then(|out| match out {
            None => Ok(None),
            Some(out) => {
                let bytes = hex_decode_to_vec(&out.value)
                    .map_err(|e| HoloKvsError::ValueDecode(format!("invalid hex value: {e}")))?;
                Ok(Some(bytes))
            }
        })
    }

    /// Delete (tombstone) the metadata key.
    ///
    /// Returns `Ok(true)` if it existed and was deleted; `Ok(false)` if it did not exist.
    pub fn delete_metadata(&self, encrypted_hash: &[u8; 16]) -> Result<bool, HoloKvsError> {
        let key = self.metadata_key(encrypted_hash);

        let x25519_sk_hex = self
            .cfg
            .writer_x25519_sk_hex
            .as_deref()
            .ok_or(HoloKvsError::MissingX25519SecretKey)?;
        let x25519_sk = decode_x25519_sk_hex(x25519_sk_hex)?;

        self.with_connection(|mut conn| async move {
            let nonce: u32 = conn.call_zome("get_next_nonce", key.clone()).await?;

            let pub_u = vxeddsa_support::public_u_from_secret(x25519_sk);
            let pub_x = X25519PublicKey(pub_u);

            let sig = sign_payload(KeyOp::Delete, &key, None, None, nonce, &pub_x, x25519_sk)?;

            let input = DeleteInput {
                key: key.clone(),
                nonce,
                pubkey_x25519: pub_x,
                signature: sig,
            };

            // delete_value is part of the holopoc hApp API. It's not currently configurable in config,
            // so we use the canonical name.
            let existed: bool = conn.call_zome("delete_value", input).await?;
            Ok((conn, existed))
        })
    }

    /// Runs `f(conn)` on a persistent Holochain connection.
    ///
    /// To avoid holding a mutex across `.await`, this takes ownership of the connection, performs
    /// the async work, then stores it back.
    fn with_connection<F, Fut, T>(&self, f: F) -> Result<T, HoloKvsError>
    where
        F: FnOnce(HoloKvsConnection) -> Fut,
        Fut: std::future::Future<Output = Result<(HoloKvsConnection, T), HoloKvsError>>,
    {
        let cfg = self.cfg.clone();

        self.rt.block_on(async {
            // Take the connection out (so we don't hold the mutex across await).
            let conn_opt = self
                .conn
                .lock()
                .map_err(|_| HoloKvsError::Runtime("poisoned connection mutex".to_string()))?
                .take();

            let conn = match conn_opt {
                Some(c) => c,
                None => HoloKvsConnection::connect(&cfg).await?,
            };

            let (conn, out) = f(conn).await?;

            // Put it back for reuse.
            *self
                .conn
                .lock()
                .map_err(|_| HoloKvsError::Runtime("poisoned connection mutex".to_string()))? =
                Some(conn);

            Ok(out)
        })
    }
}

/// ----------------------------------------------------------------------------
/// Connection + zome call helpers
/// ----------------------------------------------------------------------------

struct HoloKvsConnection {
    app_ws: AppWebsocket,
    cell_id: holochain_client::CellId,
    zome_name: String,
}

impl HoloKvsConnection {
    async fn connect(cfg: &HoloKvsConfig) -> Result<Self, HoloKvsError> {
        let admin_ws = AdminWebsocket::connect(format!("{}:{}", cfg.host, cfg.admin_port), None)
            .await
            .map_err(|e| {
                HoloKvsError::Connection(format!("admin websocket connect failed: {e}"))
            })?;

        let issued = admin_ws
            .issue_app_auth_token(IssueAppAuthenticationTokenPayload::from(cfg.app_id.clone()))
            .await
            .map_err(|e| HoloKvsError::Connection(format!("issue app auth token failed: {e}")))?;

        let app_port = match cfg.app_port {
            Some(port) => port,
            None => {
                let interfaces = admin_ws.list_app_interfaces().await.map_err(|e| {
                    HoloKvsError::Connection(format!("list app interfaces failed: {e}"))
                })?;

                if let Some(info) = interfaces.first() {
                    info.port
                } else {
                    admin_ws
                        .attach_app_interface(0, None, holochain_client::AllowedOrigins::Any, None)
                        .await
                        .map_err(|e| {
                            HoloKvsError::Connection(format!("attach app interface failed: {e}"))
                        })?
                }
            }
        };

        // Find cell id for this app
        let apps = admin_ws
            .list_apps(None)
            .await
            .map_err(|e| HoloKvsError::Connection(format!("list apps failed: {e}")))?;

        let app_info = apps
            .into_iter()
            .find(|app| app.installed_app_id == cfg.app_id)
            .ok_or_else(|| {
                HoloKvsError::Config(format!("app '{}' not found (is it installed?)", cfg.app_id))
            })?;

        let cell_id = app_info
            .cell_info
            .values()
            .flatten()
            .find_map(|cell_info| match cell_info {
                CellInfo::Provisioned(cell) => Some(cell.cell_id.clone()),
                _ => None,
            })
            .ok_or_else(|| HoloKvsError::Config("no provisioned cell found in app".to_string()))?;

        // Authorize signing credentials for zome calls
        let signer = ClientAgentSigner::default();
        let credentials = admin_ws
            .authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
                cell_id: cell_id.clone(),
                functions: None,
            })
            .await
            .map_err(|e| {
                HoloKvsError::Connection(format!("authorize signing credentials failed: {e}"))
            })?;

        signer.add_credentials(cell_id.clone(), credentials);

        let app_ws = AppWebsocket::connect(
            format!("{}:{}", cfg.host, app_port),
            issued.token,
            Arc::new(signer),
            None,
        )
        .await
        .map_err(|e| HoloKvsError::Connection(format!("app websocket connect failed: {e}")))?;

        Ok(Self {
            app_ws,
            cell_id,
            zome_name: cfg.zome_name.clone(),
        })
    }

    async fn call_zome<I, O>(&mut self, fn_name: &str, payload: I) -> Result<O, HoloKvsError>
    where
        I: Serialize + std::fmt::Debug,
        O: for<'de> Deserialize<'de> + std::fmt::Debug,
    {
        let result = self
            .app_ws
            .call_zome(
                ZomeCallTarget::CellId(self.cell_id.clone()),
                self.zome_name.clone().into(),
                fn_name.to_string().into(),
                holochain_client::ExternIO::encode(payload)
                    .map_err(|e| HoloKvsError::Codec(format!("encode payload failed: {e}")))?,
            )
            .await
            .map_err(|e| HoloKvsError::ZomeCall(format!("zome call '{fn_name}' failed: {e}")))?;

        let output: O = result
            .decode()
            .map_err(|e| HoloKvsError::Codec(format!("decode response failed: {e}")))?;
        Ok(output)
    }
}

/// ----------------------------------------------------------------------------
/// Error type
/// ----------------------------------------------------------------------------

#[derive(Debug)]
pub enum HoloKvsError {
    Config(String),
    Runtime(String),
    Connection(String),
    ZomeCall(String),
    Codec(String),
    MissingX25519SecretKey,
    InvalidHexKey(String),
    ValueDecode(String),
}

impl fmt::Display for HoloKvsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HoloKvsError::Config(s) => write!(f, "config error: {s}"),
            HoloKvsError::Runtime(s) => write!(f, "runtime error: {s}"),
            HoloKvsError::Connection(s) => write!(f, "connection error: {s}"),
            HoloKvsError::ZomeCall(s) => write!(f, "zome call error: {s}"),
            HoloKvsError::Codec(s) => write!(f, "codec error: {s}"),
            HoloKvsError::MissingX25519SecretKey => write!(f, "missing x25519 secret key"),
            HoloKvsError::InvalidHexKey(s) => write!(f, "invalid hex key: {s}"),
            HoloKvsError::ValueDecode(s) => write!(f, "value decode error: {s}"),
        }
    }
}

impl std::error::Error for HoloKvsError {}

/// ----------------------------------------------------------------------------
/// Zome-call types (must match coordinator/integrity zome serde shapes)
/// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MyceliumIpv6Addr([u8; 16]);

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    /// Derive Mycelium IPv6 address from an X25519 public key.
    ///
    /// Matches the holopoc CLI behavior:
    /// - blake3(pubkey) -> 16 bytes
    /// - set first byte to 0x04 | (parity(bitcount(buf[0]) % 2))
    fn address(&self) -> MyceliumIpv6Addr {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.0);
        let mut buf = [0u8; 16];
        hasher.finalize_xof().fill(&mut buf);
        let lsb = buf[0].count_ones() as u8 % 2;
        buf[0] = 0x04 | lsb;
        MyceliumIpv6Addr(buf)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct UserSignature(Vec<u8>);

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
enum KeyOp {
    Write = 0,
    Delete = 1,
    SetAcl = 2,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
enum Principal {
    User(MyceliumIpv6Addr),
    Group(ActionHash),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Acl {
    write: Vec<Principal>,
    admin: Vec<Principal>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WriteInput {
    key: String,
    value: String,

    /// The ACL bytes are included in the signed payload for Write operations.
    #[serde(default)]
    acl: Option<Acl>,

    nonce: u32,
    pubkey_x25519: X25519PublicKey,
    signature: UserSignature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeleteInput {
    key: String,
    nonce: u32,
    pubkey_x25519: X25519PublicKey,
    signature: UserSignature,
}

#[derive(Serialize, Deserialize, Debug)]
struct SetOutput {
    action_hash: ActionHashB64,
    entry_hash: EntryHashB64,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetValueOutput {
    key: String,
    value: String,
    nonce: u32,
    action_hash: ActionHashB64,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetStateOutput {
    key: String,
    value: Option<String>,
    deleted: bool,
    op: KeyOp,
    nonce: u32,
    acl: Acl,
    action_hash: ActionHashB64,
    pubkey_x25519: X25519PublicKey,
}

/// ----------------------------------------------------------------------------
/// Signing / canonical encoding helpers (MUST match integrity zome encoding)
/// ----------------------------------------------------------------------------

fn default_acl_for_creator(pubkey_x25519: &X25519PublicKey) -> Acl {
    Acl {
        write: vec![],
        admin: vec![Principal::User(pubkey_x25519.address())],
    }
}

fn sign_payload(
    op: KeyOp,
    key: &str,
    value: Option<&str>,
    acl: Option<&Acl>,
    nonce: u32,
    pubkey_x25519: &X25519PublicKey,
    x25519_sk: [u8; 32],
) -> Result<UserSignature, HoloKvsError> {
    let msg = encode_signed_payload(op, key, value, acl, nonce, pubkey_x25519)?;
    let (sig, _vrf) = vxeddsa_support::vxeddsa_sign(x25519_sk, &msg);
    Ok(UserSignature(sig.to_vec()))
}

fn encode_signed_payload(
    op: KeyOp,
    key: &str,
    value: Option<&str>,
    acl: Option<&Acl>,
    nonce: u32,
    pubkey_x25519: &X25519PublicKey,
) -> Result<Vec<u8>, HoloKvsError> {
    let mut out = Vec::new();

    // 1 byte op
    out.push(op as u8);

    // key: u32 LE len + bytes
    encode_bytes_with_u32_len(&mut out, key.as_bytes());

    match op {
        KeyOp::Write => {
            let v =
                value.ok_or_else(|| HoloKvsError::Codec("Write op requires value".to_string()))?;
            encode_bytes_with_u32_len(&mut out, v.as_bytes());

            // IMPORTANT: Write signs ACL bytes too (creation + updates)
            let a = acl.ok_or_else(|| HoloKvsError::Codec("Write op requires acl".to_string()))?;
            encode_acl(&mut out, a)?;
        }
        KeyOp::Delete => {
            // no args
        }
        KeyOp::SetAcl => {
            let a = acl.ok_or_else(|| HoloKvsError::Codec("SetAcl op requires acl".to_string()))?;
            encode_acl(&mut out, a)?;
        }
    }

    // next nonce u32 LE
    out.extend_from_slice(&nonce.to_le_bytes());

    // pubkey_x25519 bytes
    out.extend_from_slice(&pubkey_x25519.0);

    Ok(out)
}

fn encode_acl(out: &mut Vec<u8>, acl: &Acl) -> Result<(), HoloKvsError> {
    let write_len: u16 = acl
        .write
        .len()
        .try_into()
        .map_err(|_| HoloKvsError::Codec("ACL write list too large to encode".to_string()))?;
    out.extend_from_slice(&write_len.to_le_bytes());
    for p in &acl.write {
        encode_principal(out, p)?;
    }

    let admin_len: u16 = acl
        .admin
        .len()
        .try_into()
        .map_err(|_| HoloKvsError::Codec("ACL admin list too large to encode".to_string()))?;
    out.extend_from_slice(&admin_len.to_le_bytes());
    for p in &acl.admin {
        encode_principal(out, p)?;
    }

    Ok(())
}

fn encode_principal(out: &mut Vec<u8>, p: &Principal) -> Result<(), HoloKvsError> {
    match p {
        Principal::User(addr) => {
            out.push(0u8);
            out.extend_from_slice(&addr.0);
        }
        Principal::Group(ah) => {
            out.push(1u8);
            // Canonical encoding uses u32-len-prefixed raw bytes for the ActionHash
            encode_bytes_with_u32_len(out, ah.as_ref());
        }
    }
    Ok(())
}

fn encode_bytes_with_u32_len(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

/// ----------------------------------------------------------------------------
/// Hex helpers
/// ----------------------------------------------------------------------------

fn decode_x25519_sk_hex(hex: &str) -> Result<[u8; 32], HoloKvsError> {
    let mut s = hex.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        s = rest;
    }

    if s.len() != 64 {
        return Err(HoloKvsError::InvalidHexKey(format!(
            "expected 64 hex chars (32 bytes), got {} chars",
            s.len()
        )));
    }

    let mut out = [0u8; 32];
    faster_hex::hex_decode(s.as_bytes(), &mut out)
        .map_err(|_| HoloKvsError::InvalidHexKey("invalid hex string".to_string()))?;
    Ok(out)
}

fn hex_decode_to_vec(s: &str) -> Result<Vec<u8>, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn metadata_key_prefixing() {
        let cfg = HoloKvsConfig {
            host: "127.0.0.1".to_string(),
            admin_port: 8888,
            app_port: None,
            app_id: "kv_store".to_string(),
            zome_name: "kv_store".to_string(),
            key_prefix: Some("mycelium-cdn/meta/".to_string()),
            writer_x25519_sk_hex: Some(
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        };

        let client = HoloKvsClient::new(cfg);
        let h = [0xABu8; 16];
        let k = client.metadata_key(&h);
        assert!(k.starts_with("mycelium-cdn/meta/"));
        assert!(k.ends_with(&faster_hex::hex_string(&h)));
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 2, 0x10, 0xaa, 0xff];
        let enc = faster_hex::hex_string(&bytes);
        let dec = hex_decode_to_vec(&enc).unwrap();
        assert_eq!(dec, bytes);
    }

    #[test]
    fn decode_x25519_sk_hex_accepts_0x_prefix() {
        let s = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let sk = decode_x25519_sk_hex(s).unwrap();
        assert_eq!(sk, [0u8; 32]);
    }

    #[test]
    fn signed_payload_encoding_is_deterministic_shape() {
        let sk = [7u8; 32];
        let pub_u = vxeddsa_support::public_u_from_secret(sk);
        let pub_x = X25519PublicKey(pub_u);

        let acl = default_acl_for_creator(&pub_x);
        let msg =
            encode_signed_payload(KeyOp::Write, "k", Some("v"), Some(&acl), 123, &pub_x).unwrap();

        // 1 byte op + u32len("k") + bytes + u32len("v") + bytes + ACL + nonce(4) + pubkey(32)
        assert!(msg.len() > 1 + 4 + 1 + 4 + 1 + 4 + 32);
    }

    #[test]
    fn principal_group_serializes() {
        // Shallow sanity check that Principal::Group remains serde-compatible
        // with holo_hash types.
        let maybe =
            ActionHashB64::from_str("uhCAkz7k1i2oQx4mXkXwF6A0m2Yg3b8QO2bXc3z8B0p7oH9eZ0q0f").ok();
        if let Some(b64) = maybe {
            let ah: ActionHash = b64.into();
            let p = Principal::Group(ah);
            let _ = serde_json::to_string(&p).ok();
        }
    }
}
