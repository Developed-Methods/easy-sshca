use crate::error::{Error, Result};
use ssh_key::{
    Algorithm, PrivateKey, PublicKey,
    certificate::{Builder, CertType},
    rand_core::OsRng,
};
pub fn generate(comment: &str) -> Result<PrivateKey> {
    let mut k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    k.set_comment(comment);
    Ok(k)
}
pub fn sign(
    ca: &PrivateKey,
    public: &str,
    username: &str,
    serial: u64,
    request: &str,
    now: u64,
    duration: u64,
) -> Result<String> {
    let key = PublicKey::from_openssh(public)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(Error::input("only Ed25519 public keys are supported"));
    }
    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng,
        key.key_data().clone(),
        now.saturating_sub(300),
        now.checked_add(duration)
            .ok_or_else(|| Error::input("duration overflow"))?,
    )?;
    builder
        .serial(serial)?
        .cert_type(CertType::User)?
        .key_id(format!("{username}:{request}"))?
        .valid_principal(username)?;
    for extension in [
        "permit-pty",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-X11-forwarding",
        "permit-user-rc",
    ] {
        builder.extension(extension, "")?;
    }
    Ok(builder.sign(ca)?.to_openssh()?)
}
