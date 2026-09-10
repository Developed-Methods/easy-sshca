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
        folder.join("server/server.yaml").to_str().unwrap()
    );
    assert_eq!(
        fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut dirs: Vec<_> = fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    dirs.sort();
    assert_eq!(dirs, ["admin", "client", "server"]);
    for dir in ["admin", "client", "server"] {
        assert_eq!(
            fs::metadata(folder.join(dir)).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in fs::read_dir(folder.join(dir)).unwrap() {
            let entry = entry.unwrap();
            let mode = if entry.file_name() == "unlock.sh" {
                0o700
            } else {
                0o600
            };
            assert_eq!(entry.metadata().unwrap().permissions().mode() & 0o777, mode);
        }
    }
    let secret = fs::read_to_string(folder.join("admin/ca.bootstrap-secret")).unwrap();
    let admin = fs::read_to_string(folder.join("admin/ca.admin-key")).unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret.trim()));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(admin.trim()));
    let client_files: Vec<_> = fs::read_dir(folder.join("client"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(client_files.len(), 2);
    let template = fs::read_to_string(folder.join("client/config.yaml")).unwrap();
    assert!(template.contains("api_key: REPLACE_ME"));
    assert!(template.contains("server: https://REPLACE_ME:9443"));
    for dir in ["server", "client"] {
        for entry in fs::read_dir(folder.join(dir)).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            for credential in [secret.trim(), admin.trim()] {
                assert!(
                    !bytes
                        .windows(credential.len())
                        .any(|w| w == credential.as_bytes())
                );
            }
        }
    }
    let cert = fs::read(folder.join("server/tls.crt")).unwrap();
    assert_eq!(fs::read(folder.join("client/tls.crt")).unwrap(), cert);
    assert_eq!(fs::read(folder.join("admin/tls.crt")).unwrap(), cert);
    assert!(
        Command::new("bash")
            .arg("-n")
            .arg(folder.join("admin/unlock.sh"))
            .status()
            .unwrap()
            .success()
    );
    drop(Database::open(&folder.join("server/ca.db"), secret.trim()).unwrap());
    let original = fs::read(folder.join("server/ca.db")).unwrap();
    assert!(!init(&folder, false).status.success());
    assert_eq!(fs::read(folder.join("server/ca.db")).unwrap(), original);
    assert_eq!(
        fs::read_to_string(folder.join("admin/ca.bootstrap-secret")).unwrap(),
        secret
    );
    let moved = temp.path().join("moved");
    fs::rename(&folder, &moved).unwrap();
    let config = ServerConfig::load(&moved.join("server/server.yaml")).unwrap();
    assert_eq!(config.database, moved.join("server/ca.db"));
    let client = easy_sshca::config::ClientConfig::load(&moved.join("admin/admin.yaml")).unwrap();
    assert_eq!(client.api_key.as_deref(), Some(admin.trim()));
    assert_eq!(
        client.tls_ca.as_ref().unwrap(),
        &moved.join("admin/tls.crt")
    );
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
            .arg(folder.join("admin/admin.yaml"))
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
    let relocated_admin = temp.path().join("operator with ' quotes");
    fs::rename(folder.join("admin"), &relocated_admin).unwrap();
    let unlock = Command::new(relocated_admin.join("unlock.sh"))
        .env("EASY_SSHCA_BIN", env!("CARGO_BIN_EXE_easy-sshca"))
        .current_dir(temp.path())
        .args(["--server", &endpoint])
        .output()
        .unwrap();
    let secret = fs::read_to_string(relocated_admin.join("ca.bootstrap-secret")).unwrap();
    assert!(!String::from_utf8_lossy(&unlock.stdout).contains(secret.trim()));
    assert!(!String::from_utf8_lossy(&unlock.stderr).contains(secret.trim()));
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
    let key = easy_sshca::auth::new_key("ad");
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
    assert_eq!(
        fs::read_to_string(folder.join("admin/ca.admin-key"))
            .unwrap()
            .trim(),
        &*key
    );
    assert_eq!(fs::read_to_string(source).unwrap(), key.as_str());
    let client = easy_sshca::config::ClientConfig::load(&folder.join("admin/admin.yaml")).unwrap();
    assert_eq!(client.api_key.as_deref(), Some(key.as_str()));
}
