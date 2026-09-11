use easy_sshca::config;
use std::{
    fs,
    net::TcpListener,
    process::Command,
    time::{Duration, Instant},
};

struct Fixture(tempfile::TempDir);
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        config::exclusive(
            &dir.path().join("tls.crt"),
            tls.cert.pem().as_bytes(),
            0o600,
        )
        .unwrap();
        config::exclusive(
            &dir.path().join("tls.key"),
            tls.signing_key.serialize_pem().as_bytes(),
            0o600,
        )
        .unwrap();
        fs::write(dir.path().join("ca.db"), []).unwrap();
        config::exclusive(
            &dir.path().join("server.yaml"),
            "version: 1
database: ca.db
rpc_listen: 127.0.0.1:0
https_listen: 127.0.0.1:0
tls:
  certificate: tls.crt
  private_key: tls.key
limits:
  request_bytes: 65536
  rpc_timeout: 10s
  database_queue: 128
"
            .as_bytes(),
            0o600,
        )
        .unwrap();
        Self(dir)
    }
    fn replace(&self, from: &str, to: &str) {
        let path = self.0.path().join("server.yaml");
        fs::write(&path, fs::read_to_string(&path).unwrap().replace(from, to)).unwrap();
    }
    fn error(&self, json: bool) -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_easy-sshca"));
        cmd.args(["server", "start", "--config"])
            .arg(self.0.path().join("server.yaml"));
        if json {
            cmd.arg("--json");
        }
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("server did not report its startup error");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        String::from_utf8(if json { output.stdout } else { output.stderr }).unwrap()
    }
}

#[test]
fn missing_configuration_reports_path_and_selection_hint() {
    let f = Fixture::new();
    fs::remove_file(f.0.path().join("server.yaml")).unwrap();
    let error = f.error(false);
    assert!(
        error.contains("error: cannot read server configuration"),
        "{error}"
    );
    assert!(error.contains(f.0.path().to_str().unwrap()), "{error}");
    assert!(error.contains("--config PATH"), "{error}");
    assert!(error.contains("caused by:"), "{error}");
    let json: serde_json::Value = serde_json::from_str(&f.error(true)).unwrap();
    assert_eq!(json["error"]["reason"], "INPUT_ERROR");
    assert!(!json.to_string().contains(f.0.path().to_str().unwrap()));
}

#[test]
fn invalid_settings_identify_the_field_and_config() {
    for (from, to, field) in [
        (
            "request_bytes: 65536",
            "request_bytes: 1",
            "limits.request_bytes",
        ),
        (
            "database_queue: 128",
            "database_queue: 0",
            "limits.database_queue",
        ),
        (
            "rpc_timeout: 10s",
            "rpc_timeout: nonsense",
            "limits.rpc_timeout",
        ),
    ] {
        let f = Fixture::new();
        f.replace(from, to);
        let error = f.error(false);
        assert!(error.contains(field), "{error}");
        assert!(error.contains("server.yaml"), "{error}");
    }
}

#[test]
fn missing_tls_and_database_files_report_resolved_paths() {
    for name in ["tls.crt", "tls.key", "ca.db"] {
        let f = Fixture::new();
        let path = f.0.path().join(name);
        fs::remove_file(&path).unwrap();
        let error = f.error(false);
        assert!(error.contains(path.to_str().unwrap()), "{error}");
        if name == "ca.db" {
            assert!(error.contains("server init"), "{error}");
        }
    }
    let f = Fixture::new();
    f.replace("database: ca.db", "database: missing/ca.db");
    assert!(f.error(false).contains("server init"));
}

#[test]
fn malformed_tls_and_database_lock_errors_are_actionable() {
    let f = Fixture::new();
    fs::write(f.0.path().join("tls.key"), "not a private key").unwrap();
    let error = f.error(false);
    assert!(error.contains("cannot configure TLS"), "{error}");
    assert!(
        error.contains("tls.key") && error.contains("PEM"),
        "{error}"
    );

    let f = Fixture::new();
    let _lock = easy_sshca::storage::lock(&f.0.path().join("ca.db")).unwrap();
    let error = f.error(false);
    assert!(error.contains("cannot acquire lock"), "{error}");
    assert!(
        error.contains("ca.db.lock") && error.contains("Another process"),
        "{error}"
    );
}

#[test]
fn occupied_ports_identify_the_listener_and_address() {
    for (field, label) in [("rpc_listen", "RPC"), ("https_listen", "HTTPS")] {
        let f = Fixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        f.replace(
            &format!("{field}: 127.0.0.1:0"),
            &format!("{field}: {address}"),
        );
        let error = f.error(false);
        assert!(
            error.contains(&format!("{label} listener {address} failed")),
            "{error}"
        );
        assert!(error.contains("port is available"), "{error}");
    }
}

#[test]
fn private_key_permissions_and_file_type_have_distinct_remedies() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let key = f.0.path().join("tls.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let error = f.error(false);
    assert!(error.contains("chmod 600"), "{error}");
    assert!(error.contains(key.to_str().unwrap()), "{error}");
    fs::remove_file(&key).unwrap();
    fs::create_dir(&key).unwrap();
    let error = f.error(false);
    assert!(error.contains("must be a regular file"), "{error}");
    assert!(!error.contains("chmod"), "{error}");
}

#[test]
fn malformed_server_config_does_not_echo_secret_values() {
    let f = Fixture::new();
    let secret = "SECRET_ACCIDENTALLY_PASTED_IN_CONFIG";
    f.replace("request_bytes: 65536", &format!("request_bytes: {secret}"));
    let error = f.error(false);
    assert!(error.contains("invalid server YAML"), "{error}");
    assert!(error.contains("Server failed"), "{error}");
    assert!(!error.contains(secret));
}

#[test]
fn inline_tls_config_requires_private_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let path = f.0.path().join("server.yaml");
    let mut server = config::ServerConfig::load(&path).unwrap();
    let key = server.private_key_pem().unwrap();
    server.tls.private_key = None;
    server.tls.private_key_pem = Some(key.to_string());
    fs::write(&path, serde_saphyr::to_string(&server).unwrap()).unwrap();
    assert_eq!(
        config::ServerConfig::load(&path)
            .unwrap()
            .private_key_pem()
            .unwrap()
            .as_str(),
        key.as_str()
    );

    for mode in [0o644, 0o640, 0o620] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(config::ServerConfig::load(&path).is_err());
        let error = f.error(false);
        assert!(
            error.contains("cannot read server configuration"),
            "{error}"
        );
        assert!(error.contains("chmod 600"), "{error}");
        assert!(error.contains(path.to_str().unwrap()), "{error}");
        assert!(!error.contains(key.as_str()), "{error}");
    }
}

#[test]
fn server_config_rejects_symbolic_links() {
    let f = Fixture::new();
    let path = f.0.path().join("server.yaml");
    let target = f.0.path().join("real-server.yaml");
    fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(config::ServerConfig::load(&target).is_ok());
    assert!(config::ServerConfig::load(&path).is_err());
    let error = f.error(false);
    assert!(error.contains("symbolic links are not allowed"), "{error}");
    assert!(error.contains(path.to_str().unwrap()), "{error}");
}

#[test]
fn metrics_rejects_public_bind_addresses() {
    for address in ["0.0.0.0:9445", "[::]:9445", "192.0.2.1:9445"] {
        let f = Fixture::new();
        f.replace(
            "https_listen: 127.0.0.1:0",
            &format!("https_listen: 127.0.0.1:0\nmetrics_listen: '{address}'"),
        );
        let error = f.error(false);
        assert!(
            error.contains("metrics_listen must use a loopback address"),
            "{error}"
        );
    }
}
