use std::{error::Error, fs::Permissions, os::unix::fs::PermissionsExt, process::Stdio};

use ssh_key::{PrivateKey, PublicKey};
use tokio::process::Command;

use crate::config::SignDuration;

pub async fn generate_ed25519(comment: &str) -> std::io::Result<PrivateKey> {
    let tmp = temp_dir::TempDir::new()?;
    let output = format!("{}/id_ed25519", tmp.path().to_string_lossy());

    let mut task = Command::new("ssh-keygen")
        .args([
            /* key type */
            "-t", "ed25519",
            "-C", comment,
            /* no password */
            "-N", "",
            /* output file path */
            "-f", &output
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let _status = task.wait().await?;
    let s = tokio::fs::read(&output).await?;
    ssh_key::PrivateKey::from_openssh(&s).map_err(io_other)
}

pub async fn sign_key(ca: &PrivateKey, subject: &PublicKey, identity: &str, user: &str, valid: SignDuration) -> std::io::Result<String> {
    let tmp = temp_dir::TempDir::new()?;
    let ca_file = format!("{}/id_ca", tmp.path().to_string_lossy());
    let pub_file = format!("{}/id_ed25519.pub", tmp.path().to_string_lossy());
    let pub_crt_file = format!("{}/id_ed25519-cert.pub", tmp.path().to_string_lossy());

    let ca_priv_str = ca.to_openssh(ssh_key::LineEnding::LF).map_err(io_other)?.to_string();
    let ca_pub_str = ca.public_key().to_openssh().map_err(io_other)?;
    let subject_pub_str = subject.to_openssh().map_err(io_other)?;

    // println!("CA private:\n{}", ca_priv_str);
    // println!("CA public:\n{}", ca_pub_str);
    // println!("subject public:\n{}", subject_pub_str);

    /* write CA files */
    tokio::fs::write(&ca_file, ca_priv_str).await?;
    tokio::fs::write(format!("{}.pub", ca_file), ca_pub_str).await?;

    /* write key to sign */
    tokio::fs::write(&pub_file, subject_pub_str).await?;

    /* set permissions for private key, otherwise ssh-keygen will fail */
    tokio::fs::set_permissions(&ca_file, Permissions::from_mode(0o600)).await?;

    let mut task = Command::new("ssh-keygen")
        .args([
            "-q",
            "-I", identity,
            "-s", &ca_file,
            "-n", user,
            "-V", valid.openssh_str(),
            &pub_file,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let _status = task.wait().await?;
    let s = tokio::fs::read_to_string(&pub_crt_file).await?;

    Ok(s)
}

fn io_other<E>(error: E) -> std::io::Error where E: Into<Box<dyn Error + Send + Sync>> {
    std::io::Error::new(std::io::ErrorKind::Other, error)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn ssh_keygen_ed25519_test() {
        generate_ed25519("test@dev").await.unwrap();
    }

    #[tokio::test]
    async fn ssh_keygen_sign_test() {
        let ca = generate_ed25519("ca@dev").await.unwrap();
        let client = generate_ed25519("client@dev").await.unwrap();
        let public_key = client.public_key();

        let result = sign_key(&ca, public_key, "patrick", "plorio", SignDuration::Day).await.unwrap();
        println!("{}", result);
    }
}

