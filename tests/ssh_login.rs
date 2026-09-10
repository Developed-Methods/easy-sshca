use easy_sshca::{auth, config, protocol::Command, signing, storage::Database};
use std::{
    process::{Command as Process, Stdio},
    time::Duration,
};
fn request() -> Command {
    Command {
        request_id: auth::id(),
        ..Default::default()
    }
}
struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "requires /usr/sbin/sshd and a login-capable local account"]
fn certificate_login_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let username = String::from_utf8(Process::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let host = signing::generate("host").unwrap();
    let client = signing::generate("client").unwrap();
    config::exclusive(
        &root.join("host"),
        host.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    config::exclusive(
        &root.join("client"),
        client
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
        0o600,
    )
    .unwrap();
    let secret = auth::random_secret();
    let admin = auth::new_key("ad");
    let dbpath = root.join("ca.db");
    Database::initialize(&dbpath, &secret, &admin, "SSH login test").unwrap();
    let mut db = Database::open(&dbpath, &secret).unwrap();
    db.execute(
        "CreateZone",
        &admin,
        &Command {
            name: "test".into(),
            max_duration: 60,
            ..request()
        },
    )
    .unwrap();
    db.execute(
        "CreateUser",
        &admin,
        &Command {
            name: username.clone(),
            max_duration: 60,
            ..request()
        },
    )
    .unwrap();
    db.execute(
        "GrantZone",
        &admin,
        &Command {
            user: username.clone(),
            zone: "test".into(),
            ..request()
        },
    )
    .unwrap();
    let token = db
        .execute(
            "CreateAccessToken",
            &admin,
            &Command {
                user: username.clone(),
                name: "test".into(),
                max_duration: 60,
                ..request()
            },
        )
        .unwrap()
        .api_key;
    let ca = db
        .execute(
            "GetPublicKey",
            "",
            &Command {
                zone: "test".into(),
                ..request()
            },
        )
        .unwrap();
    std::fs::write(root.join("ca.pub"), ca.public_key).unwrap();
    let signed = db
        .execute(
            "SignCertificate",
            &token,
            &Command {
                zone: "test".into(),
                public_key: client.public_key().to_openssh().unwrap(),
                duration: 5,
                ..request()
            },
        )
        .unwrap();
    std::fs::write(root.join("client-cert.pub"), signed.certificate).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    std::fs::write(root.join("sshd_config"),format!("ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nPidFile {}\nTrustedUserCAKeys {}\nAuthorizedKeysFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel VERBOSE\nAllowUsers {username}\n",root.join("host").display(),root.join("sshd.pid").display(),root.join("ca.pub").display())).unwrap();
    let mut daemon = Daemon(
        Process::new("/usr/sbin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(root.join("sshd_config"))
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(root.join("sshd.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        if daemon.0.try_wait().unwrap().is_some() {
            panic!(
                "sshd failed: {}",
                std::fs::read_to_string(root.join("sshd.log")).unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let login = || {
        Process::new("ssh")
            .args([
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=3",
                "-p",
                &port.to_string(),
                "-i",
            ])
            .arg(root.join("client"))
            .arg(format!("{username}@127.0.0.1"))
            .arg("true")
            .output()
            .unwrap()
    };
    let result = login();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stderr),
        std::fs::read_to_string(root.join("sshd.log")).unwrap()
    );
    while auth::now() <= signed.expires_at {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(!login().status.success());
}
