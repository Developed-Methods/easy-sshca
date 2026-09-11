use easy_sshca::{config::ServerConfig, storage::Database};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn init(folder: &Path, json: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_easy-sshca"));
    command
        .args(["server", "init", "--name", "Test CA", "--folder"])
        .arg(folder);
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

#[test]
fn init_creates_private_complete_instance_and_refuses_overwrites() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("instance");
    let output = init(&folder, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["result"]["server_config"],
        folder.join("server.yaml").to_str().unwrap()
    );
    assert_eq!(
        fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut files: Vec<_> = fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    files.sort();
    assert_eq!(files, ["admin.yaml", "ca.db", "ca.db.lock", "server.yaml"]);
    for file in ["admin.yaml", "ca.db", "ca.db.lock", "server.yaml"] {
        assert_eq!(
            fs::metadata(folder.join(file))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let client = easy_sshca::config::ClientConfig::load(&folder.join("admin.yaml")).unwrap();
    let secret = client.bootstrap_secret_value().unwrap().unwrap();
    let admin = client.api_key_value().unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret.as_str()));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(admin.as_str()));
    let config = ServerConfig::load(&folder.join("server.yaml")).unwrap();
    assert!(config.tls.certificate.is_none());
    assert!(config.tls.private_key.is_none());
    assert_eq!(
        client.tls_pem().unwrap().unwrap().as_bytes(),
        config.certificate_pem().unwrap()
    );
    drop(Database::open(&folder.join("ca.db"), &secret).unwrap());
    let original = fs::read(folder.join("ca.db")).unwrap();
    assert!(!init(&folder, false).status.success());
    assert_eq!(fs::read(folder.join("ca.db")).unwrap(), original);
    let moved = temp.path().join("moved");
    fs::rename(&folder, &moved).unwrap();
    let config = ServerConfig::load(&moved.join("server.yaml")).unwrap();
    assert_eq!(config.database, moved.join("ca.db"));
    let moved_client = easy_sshca::config::ClientConfig::load(&moved.join("admin.yaml")).unwrap();
    assert_eq!(moved_client.api_key.as_deref(), Some(admin.as_str()));
    assert_eq!(
        moved_client.bootstrap_secret.as_deref(),
        Some(secret.as_str())
    );
    assert!(moved_client.tls_ca.is_none());
    assert!(moved_client.tls_ca_pem.is_some());
}

#[test]
fn existing_empty_folder_and_invalid_name_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let output = init(temp.path(), false);
    assert!(!output.status.success());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    let folder = temp.path().join("invalid");
    let output = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .args(["server", "init", "--name", "", "--folder"])
        .arg(&folder)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!folder.exists());
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn printed_command_starts_server_and_generated_client_can_unlock() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("CA with ' quotes $(touch INJECTED)");
    let output = init(&folder, false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let command = stdout
        .lines()
        .find(|line| line.contains(" server start --config "))
        .unwrap();
    assert!(command.contains("server start --config"));
    let rpc = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc_addr = rpc.local_addr().unwrap();
    let https_addr = https.local_addr().unwrap();
    drop((rpc, https));
    let mut server = Server(
        Command::new("sh")
            .args([
                "-c",
                &format!("exec {command} --rpc-listen {rpc_addr} --https-listen {https_addr}"),
            ])
            .current_dir(temp.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let endpoint = format!("https://localhost:{}", rpc_addr.port());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
            .arg("--config")
            .arg(folder.join("admin.yaml"))
            .args(["server", "status", "--server", &endpoint])
            .output()
            .unwrap();
        if status.status.success() {
            break;
        }
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "printed command exited"
        );
        assert!(Instant::now() < deadline, "server never became reachable");
        std::thread::sleep(Duration::from_millis(50));
    }
    let relocated_admin = temp.path().join("operator with ' quotes.yaml");
    fs::rename(folder.join("admin.yaml"), &relocated_admin).unwrap();
    let unlock = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .arg("--config")
        .arg(&relocated_admin)
        .args(["server", "unlock"])
        .current_dir(temp.path())
        .args(["--server", &endpoint])
        .output()
        .unwrap();
    let client = easy_sshca::config::ClientConfig::load(&relocated_admin).unwrap();
    let secret = client.bootstrap_secret_value().unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&unlock.stdout).contains(secret.as_str()));
    assert!(!String::from_utf8_lossy(&unlock.stderr).contains(secret.as_str()));
    assert!(
        unlock.status.success(),
        "{}",
        String::from_utf8_lossy(&unlock.stderr)
    );
    assert!(!temp.path().join("INJECTED").exists());
}

#[test]
fn supplied_admin_key_is_copied_into_the_instance() {
    let temp = tempfile::tempdir().unwrap();
    let key = easy_sshca::auth::new_key(easy_sshca::auth::KeyKind::Admin);
    let source = temp.path().join("admin-key");
    easy_sshca::config::exclusive(&source, key.as_bytes(), 0o600).unwrap();
    let folder = temp.path().join("instance");
    let output = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .args(["server", "init", "--name", "Existing admin", "--folder"])
        .arg(&folder)
        .arg("--admin-api-key-file")
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(source).unwrap(), key.as_str());
    let client = easy_sshca::config::ClientConfig::load(&folder.join("admin.yaml")).unwrap();
    assert_eq!(client.api_key.as_deref(), Some(key.as_str()));
}

#[test]
fn server_address_defaults_and_overrides() {
    use easy_sshca::config::server_address;
    for (input, port, expected) in [
        ("ca.example.com", None, "https://ca.example.com:9443"),
        (
            "https://ca.example.com",
            None,
            "https://ca.example.com:9443",
        ),
        ("ca.example.com:1234", None, "https://ca.example.com:1234"),
        (
            "https://ca.example.com:443/",
            None,
            "https://ca.example.com:443",
        ),
        (
            "ca.example.com:1234",
            Some(4321),
            "https://ca.example.com:4321",
        ),
        ("127.0.0.1", None, "https://127.0.0.1:9443"),
        ("[::1]", None, "https://[::1]:9443"),
        ("https://[::1]:443", None, "https://[::1]:443"),
    ] {
        let result = server_address(input, port).unwrap();
        assert_eq!(result, expected);
        assert_eq!(server_address(&result, None).unwrap(), expected);
    }
    for input in [
        "",
        "http://example.com",
        "example.com/path",
        "user@example.com",
        "example.com?query",
        "example.com:0",
        "example.com:65536",
        "example.com:bad",
    ] {
        assert!(server_address(input, None).is_err(), "{input}");
    }
    assert!(server_address("example.com", Some(0)).is_err());
}

#[test]
fn init_persists_advertised_address_and_independent_listeners() {
    let temp = tempfile::tempdir().unwrap();
    for (port_args, expected_port) in [(vec![], 1234), (vec!["--port", "4321"], 4321)] {
        let folder = temp.path().join(expected_port.to_string());
        let output = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
            .args(["server", "init", "--name", "Remote CA", "--folder"])
            .arg(&folder)
            .args([
                "--server",
                "ca.example.com:1234",
                "--https-listen",
                "0.0.0.0:8443",
            ])
            .args(port_args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let server = ServerConfig::load(&folder.join("server.yaml")).unwrap();
        let client = easy_sshca::config::ClientConfig::load(&folder.join("admin.yaml")).unwrap();
        assert_eq!(
            server.server,
            format!("https://ca.example.com:{expected_port}")
        );
        assert_eq!(server.server, client.server);
        assert_eq!(server.rpc_listen.port(), expected_port);
        assert_eq!(server.https_listen, "0.0.0.0:8443".parse().unwrap());
    }
}
