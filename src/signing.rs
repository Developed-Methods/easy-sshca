//! Ed25519 CA key handling and user certificate issuance.

use crate::error::{Error, Result};
use ssh_key::{
    Algorithm, PrivateKey, PublicKey,
    certificate::{Builder, CertType},
    rand_core::OsRng,
};

const MAX_KEY_PEM_BYTES: usize = 4096;
/// Backdate certificates to tolerate clock skew between the CA and hosts.
const VALIDITY_SKEW_SECS: u64 = 300;
const EXTENSIONS: [&str; 5] = [
    "permit-pty",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-X11-forwarding",
    "permit-user-rc",
];

pub fn generate(comment: &str) -> Result<PrivateKey> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    key.set_comment(comment);
    Ok(key)
}

/// Parse an unencrypted OpenSSH Ed25519 private key for use as a zone CA.
pub fn import(pem: &str) -> Result<PrivateKey> {
    if pem.len() > MAX_KEY_PEM_BYTES {
        return Err(Error::input("CA private key input exceeds 4096 bytes"));
    }
    let key = PrivateKey::from_openssh(pem).map_err(|_| {
        Error::input("invalid OpenSSH CA private key; provide an unencrypted Ed25519 private key")
    })?;
    if key.is_encrypted() {
        return Err(Error::input(
            "encrypted CA private keys are not supported; provide an unencrypted Ed25519 private key",
        ));
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(Error::input("only Ed25519 CA private keys are supported"));
    }
    Ok(key)
}

/// Inputs for one user certificate.
pub struct CertificateRequest<'a> {
    /// The OpenSSH public key to certify.
    pub public_key: &'a str,
    /// The single principal the certificate is valid for.
    pub principal: &'a str,
    pub serial: u64,
    /// Request UUID, recorded in the certificate key id for tracing.
    pub request_id: &'a str,
    pub now: u64,
    pub duration: u64,
}

pub fn sign(ca: &PrivateKey, request: &CertificateRequest<'_>) -> Result<String> {
    let key = PublicKey::from_openssh(request.public_key)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(Error::input("only Ed25519 public keys are supported"));
    }
    let valid_after = request.now.saturating_sub(VALIDITY_SKEW_SECS);
    let valid_before = request
        .now
        .checked_add(request.duration)
        .ok_or_else(|| Error::input("duration overflow"))?;
    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng,
        key.key_data().clone(),
        valid_after,
        valid_before,
    )?;
    builder
        .serial(request.serial)?
        .cert_type(CertType::User)?
        .key_id(format!("{}:{}", request.principal, request.request_id))?
        .valid_principal(request.principal)?;
    for extension in EXTENSIONS {
        builder.extension(extension, "")?;
    }
    Ok(builder.sign(ca)?.to_openssh()?)
}
