//! Credential formats, input validation and TOTP verification.

use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_NAME_LEN: usize = 64;
const MAX_DURATION_SECS: u64 = 365 * 86_400;
const SECRET_BYTES: usize = 32;
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_PERIOD_SECS: u64 = 30;
const TOTP_DIGITS: u32 = 6;
const BASE32: base32::Alphabet = base32::Alphabet::Rfc4648 { padding: false };

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_secs()
}

/// A fresh time-ordered identifier, used for request ids and database keys.
pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

pub fn validate_request_id(value: &str) -> Result<()> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| Error::input("request_id must be a UUIDv7"))?;
    if parsed.get_version_num() != 7 || parsed.to_string() != value {
        return Err(Error::input("request_id must be a canonical UUIDv7"));
    }
    Ok(())
}

/// Zone, user and token names: 1–64 ASCII letters, digits, `_` or `-`.
pub fn validate_name(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_NAME_LEN
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    if !valid {
        return Err(Error::input(
            "names require 1–64 ASCII letters, digits, underscores or hyphens",
        ));
    }
    Ok(())
}

pub fn validate_duration(seconds: u64) -> Result<u64> {
    if seconds == 0 || seconds > MAX_DURATION_SECS {
        return Err(Error::input(
            "duration must be between one second and 365 days",
        ));
    }
    Ok(seconds)
}

/// Parse a human duration such as `1d` or `12h` into whole seconds.
pub fn parse_duration(value: &str) -> Result<u64> {
    let duration =
        humantime::parse_duration(value).map_err(|_| Error::input("invalid duration"))?;
    if duration.subsec_nanos() != 0 {
        return Err(Error::input("duration must use whole seconds"));
    }
    validate_duration(duration.as_secs())
}

/// A random 32-byte secret encoded as unpadded Base64url.
pub fn random_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
    OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(URL_SAFE_NO_PAD.encode(*bytes))
}

/// Decode a bootstrap secret produced by [`random_secret`].
pub fn parse_bootstrap_secret(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::input("invalid bootstrap secret format"))?;
    if bytes.len() != SECRET_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::input("bootstrap secret requires 32 Base64url bytes"));
    }
    Ok(Zeroizing::new(bytes))
}

/// The two kinds of API key, distinguished by the tag in `esca_<tag>_<id>_<secret>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    AccessToken,
    Admin,
}

impl KeyKind {
    /// The short form used inside keys and in audit events.
    pub fn tag(self) -> &'static str {
        match self {
            KeyKind::AccessToken => "at",
            KeyKind::Admin => "ad",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "at" => Some(KeyKind::AccessToken),
            "ad" => Some(KeyKind::Admin),
            _ => None,
        }
    }
}

/// Mint a new API key. The returned string is the only copy of the secret.
pub fn new_key(kind: KeyKind) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "esca_{}_{}_{}",
        kind.tag(),
        new_id(),
        *random_secret()
    ))
}

/// The verifiable parts of an API key: its kind, lookup id and secret digest.
pub struct Key {
    pub kind: KeyKind,
    pub id: String,
    pub digest: Vec<u8>,
}

/// Parse an API key. Every malformed input maps to the same authentication error.
pub fn parse_key(value: &str) -> Result<Key> {
    let mut parts = value.splitn(4, '_');
    let (Some("esca"), Some(tag), Some(id), Some(secret)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::auth());
    };
    let kind = KeyKind::from_tag(tag).ok_or_else(Error::auth)?;
    validate_request_id(id).map_err(|_| Error::auth())?;
    let secret = parse_bootstrap_secret(secret).map_err(|_| Error::auth())?;
    Ok(Key {
        kind,
        id: id.into(),
        digest: hash(&secret),
    })
}

pub fn hash(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// A random Base32 TOTP secret compatible with authenticator apps.
pub fn totp_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; TOTP_SECRET_BYTES]);
    OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(base32::encode(BASE32, &*bytes))
}

/// Verify a TOTP code against the current step and its neighbours.
///
/// Returns the accepted step so callers can persist it and reject replays.
/// Steps at or before `last_step` are never accepted.
pub fn verify_totp(secret: &str, code: &str, last_step: i64, time: u64) -> Result<i64> {
    if code.is_empty() {
        return Err(Error::new(
            tonic::Code::Unauthenticated,
            "TOTP_REQUIRED",
            "TOTP code required",
        ));
    }
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new(
            tonic::Code::Unauthenticated,
            "INVALID_TOTP",
            "invalid TOTP code",
        ));
    }
    let secret = Zeroizing::new(base32::decode(BASE32, secret).ok_or_else(Error::internal)?);
    let current = (time / TOTP_PERIOD_SECS) as i64;
    for step in [current, current - 1, current + 1] {
        let expected = Zeroizing::new(totp_lite::totp_custom::<totp_lite::Sha1>(
            TOTP_PERIOD_SECS,
            TOTP_DIGITS,
            &secret,
            step.max(0) as u64 * TOTP_PERIOD_SECS,
        ));
        if step > last_step && constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Ok(step);
        }
    }
    Err(Error::new(
        tonic::Code::Unauthenticated,
        "INVALID_TOTP",
        "invalid or replayed TOTP code",
    ))
}
