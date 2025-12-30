use std::{
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// A small, focused Hero Redis client used by `mycdnctl` to store shard blobs.
///
/// Hero Redis is Redis protocol compatible, but authentication is typically:
/// 1) `CHALLENGE` -> server returns a challenge (usually hex)
/// 2) `TOKEN <pubkey_hex> <signature_hex>` -> server returns a session token
/// 3) `AUTH <token>` -> standard Redis AUTH
/// 4) `SELECT <db>` -> choose database
///
/// This module supports:
/// - Logging in directly with a pre-existing token (`AUTH <token>`)
/// - Performing `CHALLENGE`/`TOKEN` if you can provide `pubkey_hex` + `signature_hex`
/// - Performing `CHALLENGE`/sign/`TOKEN`/`AUTH` using an Ed25519 private key (feature-gated)
///
/// Ed25519 signing support is feature-gated to avoid forcing extra crypto deps on all builds.
/// - When built with feature `hero_redis_ed25519`, [`HeroRedis::login_with_private_key_hex`]
///   will sign the server challenge and complete the login flow.
/// - Without that feature, calling `login_with_private_key_hex` will return
///   [`HeroRedisError::Ed25519SupportNotEnabled`].
pub struct HeroRedis {
    con: redis::Connection,
    selected_db: Option<u16>,
}

#[derive(Debug)]
pub enum HeroRedisError {
    Redis(redis::RedisError),
    InvalidHex { what: &'static str },
    InvalidChallengeFormat { details: String },
    InvalidSignatureLength { got: usize, expected: usize },
    InvalidPrivateKeyLength { got: usize, expected: usize },
    Ed25519SupportNotEnabled,
    AuthRequired,
}

impl fmt::Display for HeroRedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeroRedisError::Redis(e) => write!(f, "redis error: {e}"),
            HeroRedisError::InvalidHex { what } => write!(f, "invalid hex in {what}"),
            HeroRedisError::InvalidChallengeFormat { details } => {
                write!(f, "invalid challenge format: {details}")
            }
            HeroRedisError::InvalidSignatureLength { got, expected } => write!(
                f,
                "invalid signature length: got {got} bytes, expected {expected} bytes"
            ),
            HeroRedisError::InvalidPrivateKeyLength { got, expected } => write!(
                f,
                "invalid private key length: got {got} bytes, expected {expected} bytes"
            ),
            HeroRedisError::Ed25519SupportNotEnabled => write!(
                f,
                "ed25519 signing support not enabled (build with feature `hero_redis_ed25519`)"
            ),
            HeroRedisError::AuthRequired => write!(f, "hero redis requires authentication"),
        }
    }
}

impl std::error::Error for HeroRedisError {}

impl From<redis::RedisError> for HeroRedisError {
    fn from(value: redis::RedisError) -> Self {
        HeroRedisError::Redis(value)
    }
}

/// How to treat the challenge returned by Hero Redis for signing purposes.
#[derive(Debug, Clone, Copy)]
pub enum ChallengeFormat {
    /// Interpret the challenge as hex and sign the decoded bytes.
    ///
    /// This is the most common interpretation when the server returns a 64-char hex string.
    HexDecodedBytes,
    /// Sign the UTF-8 bytes of the challenge string as returned.
    ///
    /// Use this if the server expects the exact string bytes to be signed.
    Utf8Bytes,
}

/// A login result that can be cached by the caller.
#[derive(Debug, Clone)]
pub struct HeroLoginToken {
    pub token: String,
    pub obtained_at: Instant,
}

impl HeroLoginToken {
    pub fn new(token: String) -> Self {
        Self {
            token,
            obtained_at: Instant::now(),
        }
    }

    /// Convenience helper if you want to treat the token as "fresh" for some time.
    /// (Hero Redis token TTL is server-defined; this is only a caller-side heuristic.)
    pub fn is_younger_than(&self, max_age: Duration) -> bool {
        self.obtained_at.elapsed() <= max_age
    }
}

impl HeroRedis {
    /// Connect to a Hero Redis server.
    ///
    /// This does not authenticate or select a DB. Use:
    /// - [`HeroRedis::login_with_token`] or
    /// - [`HeroRedis::login_with_challenge_signature`]
    pub fn connect(host: SocketAddr) -> Result<Self, HeroRedisError> {
        let client = redis::Client::open(format!("redis://{host}"))?;
        let con = client.get_connection()?;
        Ok(Self {
            con,
            selected_db: None,
        })
    }

    /// Authenticate with an already-issued token (standard Redis `AUTH <token>`).
    /// Optionally selects a database.
    pub fn login_with_token(
        mut self,
        token: &str,
        db: Option<u16>,
    ) -> Result<Self, HeroRedisError> {
        // Standard Redis AUTH
        redis::cmd("AUTH").arg(token).query::<()>(&mut self.con)?;

        if let Some(db) = db {
            self.select(db)?;
        }

        Ok(self)
    }

    /// Perform `CHALLENGE` + Ed25519 signing + `TOKEN` + `AUTH`, using a hex-encoded private key.
    ///
    /// - `private_key_hex` must be 64 hex chars (32 bytes)
    /// - `challenge_format` controls whether we sign the decoded hex bytes or the UTF-8 bytes
    ///   of the returned challenge string
    /// - `db` selects a database after authentication
    ///
    /// This method requires building with feature `hero_redis_ed25519`. Without it, this method
    /// returns [`HeroRedisError::Ed25519SupportNotEnabled`].
    pub fn login_with_private_key_hex(
        mut self,
        private_key_hex: &str,
        challenge_format: ChallengeFormat,
        db: Option<u16>,
    ) -> Result<(Self, HeroLoginToken), HeroRedisError> {
        let pk_bytes = hex_decode(private_key_hex).map_err(|_| HeroRedisError::InvalidHex {
            what: "private_key_hex",
        })?;

        let got = pk_bytes.len();
        let private_key: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| HeroRedisError::InvalidPrivateKeyLength { got, expected: 32 })?;

        // 1) CHALLENGE
        let challenge_str = self.challenge()?;
        let challenge_bytes: Vec<u8> = match challenge_format {
            ChallengeFormat::HexDecodedBytes => {
                hex_decode(&challenge_str).map_err(|_| HeroRedisError::InvalidChallengeFormat {
                    details: format!(
                        "expected hex challenge, got {:?}",
                        truncate_for_log(&challenge_str, 128)
                    ),
                })?
            }
            ChallengeFormat::Utf8Bytes => challenge_str.as_bytes().to_vec(),
        };

        // 2) SIGN + TOKEN
        let (pubkey_hex, signature_hex) =
            ed25519_pubkey_and_signature_hex(&private_key, &challenge_bytes)?;
        let token = self.token(&pubkey_hex, &signature_hex)?;

        // 3) AUTH with token
        redis::cmd("AUTH").arg(&token).query::<()>(&mut self.con)?;

        // 4) SELECT
        if let Some(db) = db {
            self.select(db)?;
        }

        Ok((self, HeroLoginToken::new(token)))
    }

    /// Perform `CHALLENGE` + `TOKEN` using a *precomputed* signature.
    ///
    /// - `pubkey_hex`: 64 hex chars (32 bytes)
    /// - `signature_hex`: 128 hex chars (64 bytes)
    ///
    /// Returns a session token which is then used for `AUTH`, and optionally selects `db`.
    pub fn login_with_challenge_signature(
        mut self,
        pubkey_hex: &str,
        signature_hex: &str,
        db: Option<u16>,
    ) -> Result<(Self, HeroLoginToken), HeroRedisError> {
        // Step 1: get a challenge (we don't actually need it here, but calling it
        // makes this flow explicit and keeps server-side state aligned if the server
        // expects CHALLENGE before TOKEN).
        let _challenge = self.challenge()?;

        // Step 2: exchange token
        let token = self.token(pubkey_hex, signature_hex)?;
        // Step 3: AUTH with token
        redis::cmd("AUTH").arg(&token).query::<()>(&mut self.con)?;
        // Step 4: SELECT
        if let Some(db) = db {
            self.select(db)?;
        }

        Ok((self, HeroLoginToken::new(token)))
    }

    /// Fetch a new challenge from the server (`CHALLENGE`).
    ///
    /// The server typically returns a 64-character hex string.
    pub fn challenge(&mut self) -> Result<String, HeroRedisError> {
        let challenge = redis::cmd("CHALLENGE").query::<String>(&mut self.con)?;
        Ok(challenge)
    }

    /// Exchange a signed challenge for a session token (`TOKEN <pubkey> <signature>`).
    ///
    /// This call assumes you already signed the last issued challenge according to the server's
    /// expectations.
    pub fn token(
        &mut self,
        pubkey_hex: &str,
        signature_hex: &str,
    ) -> Result<String, HeroRedisError> {
        // Basic validation to catch obvious mistakes early.
        if hex_decode(pubkey_hex).is_err() {
            return Err(HeroRedisError::InvalidHex { what: "pubkey_hex" });
        }
        let sig = hex_decode(signature_hex).map_err(|_| HeroRedisError::InvalidHex {
            what: "signature_hex",
        })?;
        if sig.len() != 64 {
            return Err(HeroRedisError::InvalidSignatureLength {
                got: sig.len(),
                expected: 64,
            });
        }

        let token = redis::cmd("TOKEN")
            .arg(pubkey_hex)
            .arg(signature_hex)
            .query::<String>(&mut self.con)?;

        Ok(token)
    }

    /// Select the given Hero Redis database (`SELECT <db>`).
    pub fn select(&mut self, db: u16) -> Result<(), HeroRedisError> {
        redis::cmd("SELECT").arg(db).query::<()>(&mut self.con)?;
        self.selected_db = Some(db);
        Ok(())
    }

    /// Set a raw binary value under a raw binary key (`SET key value`).
    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), HeroRedisError> {
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query::<()>(&mut self.con)?;
        Ok(())
    }

    /// Optionally set a value with an expiry in seconds (`SETEX key seconds value`).
    pub fn set_ex(&mut self, key: &[u8], seconds: u64, value: &[u8]) -> Result<(), HeroRedisError> {
        redis::cmd("SETEX")
            .arg(key)
            .arg(seconds)
            .arg(value)
            .query::<()>(&mut self.con)?;
        Ok(())
    }

    /// Get a value (`GET key`).
    ///
    /// Returns `Ok(None)` when the key is missing.
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, HeroRedisError> {
        let v = redis::cmd("GET")
            .arg(key)
            .query::<Option<Vec<u8>>>(&mut self.con)?;
        Ok(v)
    }

    /// Delete a key (`DEL key`).
    pub fn del(&mut self, key: &[u8]) -> Result<u64, HeroRedisError> {
        let deleted = redis::cmd("DEL").arg(key).query::<u64>(&mut self.con)?;
        Ok(deleted)
    }

    /// Returns the currently selected DB if this instance selected one.
    pub fn selected_db(&self) -> Option<u16> {
        self.selected_db
    }

    /// Helper for callers that want to implement the full `CHALLENGE` -> sign -> `TOKEN` flow.
    ///
    /// You provide a `signer` closure that accepts the bytes-to-sign and returns the signature
    /// bytes (Ed25519 signature is 64 bytes).
    ///
    /// This method will:
    /// - call `CHALLENGE`
    /// - turn the returned string into bytes according to `challenge_format`
    /// - call `signer(challenge_bytes)`
    /// - call `TOKEN pubkey_hex signature_hex`
    /// - call `AUTH token`
    /// - optionally `SELECT db`
    pub fn login_with_signer<F>(
        mut self,
        pubkey_hex: &str,
        challenge_format: ChallengeFormat,
        mut signer: F,
        db: Option<u16>,
    ) -> Result<(Self, HeroLoginToken), HeroRedisError>
    where
        F: FnMut(&[u8]) -> Result<Vec<u8>, HeroRedisError>,
    {
        if hex_decode(pubkey_hex).is_err() {
            return Err(HeroRedisError::InvalidHex { what: "pubkey_hex" });
        }

        let challenge_str = self.challenge()?;
        let challenge_bytes: Vec<u8> = match challenge_format {
            ChallengeFormat::HexDecodedBytes => {
                hex_decode(&challenge_str).map_err(|_| HeroRedisError::InvalidChallengeFormat {
                    details: format!(
                        "expected hex challenge, got {:?}",
                        truncate_for_log(&challenge_str, 128)
                    ),
                })?
            }
            ChallengeFormat::Utf8Bytes => challenge_str.as_bytes().to_vec(),
        };

        let sig = signer(&challenge_bytes)?;
        if sig.len() != 64 {
            return Err(HeroRedisError::InvalidSignatureLength {
                got: sig.len(),
                expected: 64,
            });
        }

        let signature_hex = hex_encode(&sig);
        let token = self.token(pubkey_hex, &signature_hex)?;
        redis::cmd("AUTH").arg(&token).query::<()>(&mut self.con)?;

        if let Some(db) = db {
            self.select(db)?;
        }

        Ok((self, HeroLoginToken::new(token)))
    }
}

/// Returns `(pubkey_hex, signature_hex)` for the given Ed25519 private key and message.
///
/// Feature-gated so `mycdnctl` can compile without crypto deps unless needed.
#[cfg(feature = "hero_redis_ed25519")]
fn ed25519_pubkey_and_signature_hex(
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<(String, String), HeroRedisError> {
    use ed25519_dalek::Signer;

    // ed25519-dalek v2: SigningKey is constructed from a 32-byte secret key.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign(message);
    let signature_bytes = signature.to_bytes();

    let pubkey_hex = hex_encode(verifying_key.as_bytes());
    let signature_hex = hex_encode(&signature_bytes);

    Ok((pubkey_hex, signature_hex))
}

#[cfg(not(feature = "hero_redis_ed25519"))]
fn ed25519_pubkey_and_signature_hex(
    _private_key: &[u8; 32],
    _message: &[u8],
) -> Result<(String, String), HeroRedisError> {
    Err(HeroRedisError::Ed25519SupportNotEnabled)
}

/// Encode bytes to lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string (upper or lower) into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(());
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex_nibble(bytes[i])?;
        let lo = from_hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }

    Ok(out)
}

fn from_hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(()),
    }
}

fn truncate_for_log(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut out = s[..max_len].to_string();
    out.push_str("...");
    out
}
