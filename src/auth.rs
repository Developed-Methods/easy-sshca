use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_secs()
}
pub fn id() -> String {
    uuid::Uuid::now_v7().to_string()
}
pub fn request_id(value: &str) -> Result<()> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| Error::input("request_id must be a UUIDv7"))?;
    if parsed.get_version_num() != 7 || parsed.to_string() != value {
        return Err(Error::input("request_id must be a canonical UUIDv7"));
    }
    Ok(())
}
pub fn name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(Error::input(
            "names require 1–64 ASCII letters, digits, underscores or hyphens",
        ));
    }
    Ok(())
}
pub fn duration(value: u64) -> Result<u64> {
    if value == 0 || value > 365 * 86400 {
        return Err(Error::input(
            "duration must be between one second and 365 days",
        ));
    }
    Ok(value)
}
pub fn parse_duration(value: &str) -> Result<u64> {
    let d = humantime::parse_duration(value).map_err(|_| Error::input("invalid duration"))?;
    if d.subsec_nanos() != 0 {
        return Err(Error::input("duration must use whole seconds"));
    }
    duration(d.as_secs())
}
pub fn random_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(URL_SAFE_NO_PAD.encode(*bytes))
}
pub fn bootstrap(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::input("invalid bootstrap secret format"))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::input("bootstrap secret requires 32 Base64url bytes"));
    }
    Ok(Zeroizing::new(bytes))
}
pub fn new_key(kind: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("esca_{kind}_{}_{}", id(), *random_secret()))
}
pub struct Key {
    pub kind: String,
    pub id: String,
    pub digest: Vec<u8>,
}
pub fn key(value: &str) -> Result<Key> {
    let mut parts = value.splitn(4, '_');
    if parts.next() != Some("esca") {
        return Err(Error::auth());
    }
    let kind = parts.next().ok_or_else(Error::auth)?;
    if kind != "at" && kind != "ad" {
        return Err(Error::auth());
    }
    let id = parts.next().ok_or_else(Error::auth)?;
    request_id(id).map_err(|_| Error::auth())?;
    let secret = bootstrap(parts.next().ok_or_else(Error::auth)?).map_err(|_| Error::auth())?;
    Ok(Key {
        kind: kind.into(),
        id: id.into(),
        digest: hash(&secret),
    })
}
pub fn hash(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}
pub fn totp_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 20]);
    OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &*bytes,
    ))
}
pub fn totp_step(secret: &str, code: &str, last: i64, time: u64) -> Result<i64> {
    if code.is_empty() {
        return Err(Error::new(
            tonic::Code::Unauthenticated,
            "TOTP_REQUIRED",
            "TOTP code required",
        ));
    }
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new(
            tonic::Code::Unauthenticated,
            "INVALID_TOTP",
            "invalid TOTP code",
        ));
    }
    let bytes = Zeroizing::new(
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(Error::internal)?,
    );
    for step in [
        (time / 30) as i64,
        (time / 30) as i64 - 1,
        (time / 30) as i64 + 1,
    ] {
        let expected = Zeroizing::new(totp_lite::totp_custom::<totp_lite::Sha1>(
            30,
            6,
            &bytes,
            step.max(0) as u64 * 30,
        ));
        if step > last && equal(expected.as_bytes(), code.as_bytes()) {
            return Ok(step);
        }
    }
    Err(Error::new(
        tonic::Code::Unauthenticated,
        "INVALID_TOTP",
        "invalid or replayed TOTP code",
    ))
}
