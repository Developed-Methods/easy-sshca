use easy_sshca::{
    auth, cli,
    config::{self, ClientConfig},
    protocol::Command,
    storage::Database,
};
use std::{
    path::PathBuf,
    process::{Child, Stdio},
    time::Duration,
};
fn cmd() -> Command {
    Command {
        request_id: auth::id(),
        ..Default::default()
    }
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
struct Server {
    dir: tempfile::TempDir,
    process: Child,
    client: ClientConfig,
    secret: String,
    https: String,
}
impl Server {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("ca.db");
        let secret = auth::random_secret().to_string();
        let admin = auth::new_key("ad").to_string();
        Database::initialize(&db, &secret, &admin, "Integration CA").unwrap();
        let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        config::exclusive(&cert, tls.cert.pem().as_bytes(), 0o600).unwrap();
        config::exclusive(&key, tls.signing_key.serialize_pem().as_bytes(), 0o600).unwrap();
        let rpc = port();
        let https = port();
        std::fs::write(dir.path().join("server.yaml"),format!("version: 1\ndatabase: {}\nrpc_listen: 127.0.0.1:{rpc}\nhttps_listen: 127.0.0.1:{https}\ntls:\n  certificate: {}\n  private_key: {}\nlimits:\n  request_bytes: 65536\n  rpc_timeout: 10s\n  database_queue: 16\n",db.display(),cert.display(),key.display())).unwrap();
        let process = Self::spawn(dir.path());
        let s = Self {
            dir,
            process,
            client: ClientConfig {
                version: 1,
                server: format!("https://localhost:{rpc}"),
                api_key: Some(admin),
                api_key_file: None,
                bootstrap_secret: None,
                bootstrap_secret_file: None,
                tls_ca: Some(cert),
                tls_ca_pem: None,
                defaults: Default::default(),
            },
            secret,
            https: format!("https://localhost:{https}"),
        };
        s.wait().await;
        s
    }
    fn spawn(path: &std::path::Path) -> Child {
        std::process::Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
            .args(["server", "start", "--config"])
            .arg(path.join("server.yaml"))
            .stdout(Stdio::null())
            .stderr(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(path.join("server.log"))
                    .unwrap(),
            )
            .spawn()
            .unwrap()
    }
    async fn wait(&self) {
        for _ in 0..100 {
            if cli::rpc(&self.client, "GetStatus", cmd()).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!(
            "server did not start: {}",
            std::fs::read_to_string(self.dir.path().join("server.log")).unwrap()
        );
    }
    async fn unlock(&self) {
        assert_eq!(
            cli::rpc(
                &self.client,
                "Unlock",
                Command {
                    secret: self.secret.clone(),
                    ..cmd()
                }
            )
            .await
            .unwrap()
            .state,
            "READY"
        );
    }
    fn http(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    &std::fs::read(self.client.tls_ca.as_ref().unwrap()).unwrap(),
                )
                .unwrap(),
            )
            .build()
            .unwrap()
    }
    async fn user(&self) -> ClientConfig {
        cli::rpc(
            &self.client,
            "CreateZone",
            Command {
                name: "production".into(),
                max_duration: 86400,
                ..cmd()
            },
        )
        .await
        .unwrap();
        cli::rpc(
            &self.client,
            "CreateUser",
            Command {
                name: "alice".into(),
                max_duration: 86400,
                ..cmd()
            },
        )
        .await
        .unwrap();
        cli::rpc(
            &self.client,
            "GrantZone",
            Command {
                user: "alice".into(),
                zone: "production".into(),
                ..cmd()
            },
        )
        .await
        .unwrap();
        let key = cli::rpc(
            &self.client,
            "CreateAccessToken",
            Command {
                user: "alice".into(),
                name: "laptop".into(),
                max_duration: 3600,
                ..cmd()
            },
        )
        .await
        .unwrap()
        .api_key;
        let mut c = self.client.clone();
        c.api_key = Some(key);
        c
    }
    fn stop(&mut self) {
        unsafe {
            libc::kill(self.process.id() as i32, libc::SIGTERM);
        }
        self.process.wait().unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
fn status(e: &anyhow::Error) -> tonic::Code {
    e.downcast_ref::<tonic::Status>().unwrap().code()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_locked_boundaries_http_restart_and_secret_logs() {
    let mut s = Server::new().await;
    let http = s.http();
    assert_eq!(
        http.get(format!("{}/health/live", s.https))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        http.get(format!("{}/health/ready", s.https))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        http.get(format!("{}/zones/production/ca.pub", s.https))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    for op in [
        "CreateZone",
        "ImportZone",
        "ListZones",
        "UpdateZone",
        "CreateUser",
        "ListUsers",
        "ListUserZones",
        "UpdateUser",
        "RemoveUser",
        "GrantZone",
        "RevokeZone",
        "CreateAccessToken",
        "ListAccessTokens",
        "UpdateAccessToken",
        "RemoveAccessToken",
        "ClearTotp",
        "RotateAdminKey",
        "BeginTotpEnrollment",
        "ConfirmTotpEnrollment",
        "RotateToken",
        "SignCertificate",
        "GetPublicKey",
    ] {
        assert_eq!(
            status(&cli::rpc(&s.client, op, cmd()).await.unwrap_err()),
            tonic::Code::FailedPrecondition,
            "{op}"
        );
    }
    assert!(
        cli::rpc(
            &s.client,
            "Unlock",
            Command {
                secret: auth::random_secret().to_string(),
                ..cmd()
            }
        )
        .await
        .is_err()
    );
    assert_eq!(
        cli::rpc(&s.client, "GetStatus", cmd()).await.unwrap().state,
        "LOCKED"
    );
    let mut untrusted = s.client.clone();
    untrusted.tls_ca = None;
    assert!(cli::channel(&untrusted).await.is_err());
    s.unlock().await;
    let user = s.user().await;
    for op in [
        "CreateZone",
        "ImportZone",
        "ListZones",
        "UpdateZone",
        "CreateUser",
        "ListUsers",
        "ListUserZones",
        "UpdateUser",
        "RemoveUser",
        "GrantZone",
        "RevokeZone",
        "CreateAccessToken",
        "ListAccessTokens",
        "UpdateAccessToken",
        "RemoveAccessToken",
        "ClearTotp",
        "RotateAdminKey",
    ] {
        assert_eq!(
            status(&cli::rpc(&user, op, cmd()).await.unwrap_err()),
            tonic::Code::PermissionDenied,
            "{op}"
        );
    }
    for op in [
        "BeginTotpEnrollment",
        "ConfirmTotpEnrollment",
        "RotateToken",
        "SignCertificate",
    ] {
        assert_eq!(
            status(&cli::rpc(&s.client, op, cmd()).await.unwrap_err()),
            tonic::Code::PermissionDenied,
            "{op}"
        );
    }
    let fetched = http
        .get(format!("{}/zones/production/ca.pub", s.https))
        .send()
        .await
        .unwrap();
    assert_eq!(fetched.status(), 200);
    let etag = fetched.headers()["etag"].clone();
    let public = fetched.text().await.unwrap();
    let rpc = cli::rpc(
        &user,
        "GetPublicKey",
        Command {
            zone: "production".into(),
            ..cmd()
        },
    )
    .await
    .unwrap();
    assert_eq!(public.trim(), rpc.public_key);
    assert_eq!(
        http.get(format!("{}/zones/production/ca.pub", s.https))
            .header("If-None-Match", etag)
            .send()
            .await
            .unwrap()
            .status(),
        304
    );
    assert_eq!(
        http.get(format!("{}/zones/missing/ca.pub", s.https))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let curl = std::process::Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--cacert"])
        .arg(s.client.tls_ca.as_ref().unwrap())
        .arg(format!("{}/zones/production/ca.pub", s.https))
        .output()
        .unwrap();
    assert!(curl.status.success());
    assert_eq!(String::from_utf8(curl.stdout).unwrap(), public);
    s.stop();
    s.process = Server::spawn(s.dir.path());
    s.wait().await;
    assert_eq!(
        cli::rpc(&s.client, "GetStatus", cmd()).await.unwrap().state,
        "LOCKED"
    );
    s.unlock().await;
    assert_eq!(
        cli::rpc(
            &user,
            "GetPublicKey",
            Command {
                zone: "production".into(),
                ..cmd()
            }
        )
        .await
        .unwrap()
        .fingerprint,
        rpc.fingerprint
    );
    let payload_secret = "DO_NOT_LOG_REQUEST_PAYLOAD";
    let rejected = cli::rpc(
        &user,
        "SignCertificate",
        Command {
            request_id: payload_secret.into(),
            secret: payload_secret.into(),
            totp: payload_secret.into(),
            replacement_key: payload_secret.into(),
            ..Default::default()
        },
    )
    .await;
    assert!(rejected.is_err());
    let enrollment = cli::rpc(&user, "BeginTotpEnrollment", cmd()).await.unwrap();
    assert!(!enrollment.secret.is_empty());
    s.stop();
    let logs = std::fs::read_to_string(s.dir.path().join("server.log")).unwrap();
    for secret in [
        payload_secret,
        &enrollment.secret,
        &enrollment.otpauth_uri,
        &s.secret,
        s.client.api_key.as_ref().unwrap(),
        user.api_key.as_ref().unwrap(),
    ] {
        assert!(!logs.contains(secret));
    }
    let private_key = std::fs::read_to_string(s.dir.path().join("tls.key")).unwrap();
    for line in private_key
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
    {
        assert!(!logs.contains(line), "TLS private key leaked into logs");
    }
    let events: Vec<serde_json::Value> = logs
        .lines()
        .map(|line| serde_json::from_str(line).expect("server logs must be structured JSON"))
        .collect();
    for message in [
        "Server starting",
        "Server configuration loaded",
        "TLS certificate and private key loaded",
        "Listener bound",
        "Server waiting for unlock; use easy-sshca server unlock",
        "Database unlocked; server ready for administration and signing",
        "Server shutting down",
        "Server stopped",
    ] {
        assert!(
            events
                .iter()
                .any(|event| event["fields"]["message"] == message),
            "missing event: {message}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["level"] == "WARN" && event["fields"]["operation"] == "Unlock")
    );
    assert!(
        events
            .iter()
            .any(|event| event["level"] == "INFO" && event["fields"]["result"] == "OK")
    );
    assert!(
        events
            .iter()
            .any(|event| event["fields"]["listener"] == "RPC"
                && event["fields"]["address"].as_str().is_some())
    );
    assert!(
        events
            .iter()
            .any(|event| event["fields"]["listener"] == "HTTPS"
                && event["fields"]["address"].as_str().is_some())
    );
}
fn run_cli(path: &std::path::Path, args: &[&str], input: Option<&str>) -> std::process::Output {
    use std::io::Write;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .arg("--config")
        .arg(path)
        .arg("--json")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_configuration_signing_rotation_and_recovery() {
    let s = Server::new().await;
    s.unlock().await;
    let user = s.user().await;
    let path = s.dir.path().join("client.yaml");
    let configured = run_cli(
        &path,
        &[
            "configure",
            "--server",
            &s.client.server,
            "--tls-ca",
            s.client.tls_ca.as_ref().unwrap().to_str().unwrap(),
            "--api-key-stdin",
            "--zone",
            "production",
        ],
        user.api_key.as_deref(),
    );
    assert!(
        configured.status.success(),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );
    let key = s.dir.path().join("id_ed25519");
    let generated = run_cli(&path, &["gen-key", "--file", key.to_str().unwrap()], None);
    assert!(generated.status.success());
    assert!(
        !run_cli(&path, &["gen-key", "--file", key.to_str().unwrap()], None)
            .status
            .success()
    );
    let public = PathBuf::from(format!("{}.pub", key.display()));
    let signed = run_cli(
        &path,
        &[
            "sign",
            "--file",
            public.to_str().unwrap(),
            "--duration",
            "12h",
        ],
        None,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&signed.stdout).unwrap();
    assert_eq!(result["result"]["effective_duration"], 3600);
    assert!(
        !run_cli(&path, &["sign", "--file", public.to_str().unwrap()], None)
            .status
            .success()
    );
    assert!(
        run_cli(
            &path,
            &["sign", "--file", public.to_str().unwrap(), "--force"],
            None
        )
        .status
        .success()
    );
    let rotated = run_cli(&path, &["rotate-token"], None);
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert!(cli::rpc(&user, "BeginTotpEnrollment", cmd()).await.is_err());
    let current = ClientConfig::load(&path).unwrap();
    let mut candidate = current.clone();
    let mut rotation = cmd();
    rotation.replacement_key = auth::new_key("at").to_string();
    candidate.api_key = Some(rotation.replacement_key.clone());
    let pending =
        serde_json::json!({"operation":"RotateToken","command":rotation,"config":candidate});
    config::exclusive(
        &path.with_extension("rotation.yaml"),
        serde_saphyr::to_string(&pending).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    cli::rpc(&current, "RotateToken", rotation).await.unwrap();
    let recovered = run_cli(&path, &["rotate-token"], None);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(
        ClientConfig::load(&path).unwrap().api_key,
        candidate.api_key
    );
    assert!(!path.with_extension("rotation.yaml").exists());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_unlock_races_and_revocation_order() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ca.db");
    let secret = auth::random_secret();
    let admin = auth::new_key("ad");
    Database::initialize(&db, &secret, &admin, "race test").unwrap();
    let s = easy_sshca::server::State::new(db, 16, Duration::from_secs(10)).unwrap();
    let (a, b) = tokio::join!(
        s.call(
            "Unlock",
            String::new(),
            Command {
                secret: secret.to_string(),
                ..cmd()
            },
            None
        ),
        s.call(
            "Unlock",
            String::new(),
            Command {
                secret: secret.to_string(),
                ..cmd()
            },
            None
        )
    );
    assert!(a.is_ok() ^ b.is_ok());
    s.call(
        "CreateZone",
        admin.to_string(),
        Command {
            name: "test".into(),
            max_duration: 60,
            ..cmd()
        },
        None,
    )
    .await
    .unwrap();
    s.call(
        "CreateUser",
        admin.to_string(),
        Command {
            name: "alice".into(),
            max_duration: 60,
            ..cmd()
        },
        None,
    )
    .await
    .unwrap();
    s.call(
        "GrantZone",
        admin.to_string(),
        Command {
            user: "alice".into(),
            zone: "test".into(),
            ..cmd()
        },
        None,
    )
    .await
    .unwrap();
    let token = s
        .call(
            "CreateAccessToken",
            admin.to_string(),
            Command {
                user: "alice".into(),
                name: "token".into(),
                max_duration: 60,
                ..cmd()
            },
            None,
        )
        .await
        .unwrap()
        .api_key;
    let public = easy_sshca::signing::generate("test")
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    let sign = s.call(
        "SignCertificate",
        token.clone(),
        Command {
            zone: "test".into(),
            public_key: public.clone(),
            ..cmd()
        },
        None,
    );
    let remove = s.call(
        "RemoveAccessToken",
        admin.to_string(),
        Command {
            user: "alice".into(),
            name: "token".into(),
            ..cmd()
        },
        None,
    );
    let (issued, removed) = tokio::join!(sign, remove);
    assert!(issued.is_ok());
    assert!(removed.is_ok());
    assert!(
        s.call(
            "SignCertificate",
            token,
            Command {
                zone: "test".into(),
                public_key: public,
                ..cmd()
            },
            None
        )
        .await
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn database_contention_bounds_queue_and_does_not_commit_expired_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    let secret = auth::random_secret();
    let admin = auth::new_key("ad");
    Database::initialize(&path, &secret, &admin, "contention").unwrap();
    let state =
        easy_sshca::server::State::new(path.clone(), 1, Duration::from_millis(100)).unwrap();
    state
        .call(
            "Unlock",
            String::new(),
            Command {
                secret: secret.to_string(),
                ..cmd()
            },
            None,
        )
        .await
        .unwrap();
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker
        .pragma_update(
            None,
            "key",
            format!("x'{}'", hex::encode(&*auth::bootstrap(&secret).unwrap())),
        )
        .unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let first = state.clone();
    let first_admin = admin.to_string();
    let first = tokio::spawn(async move {
        first
            .call(
                "CreateUser",
                first_admin,
                Command {
                    name: "first".into(),
                    max_duration: 60,
                    ..cmd()
                },
                None,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let second = state.clone();
    let second_admin = admin.to_string();
    let second = tokio::spawn(async move {
        second
            .call(
                "CreateUser",
                second_admin,
                Command {
                    name: "expired".into(),
                    max_duration: 60,
                    ..cmd()
                },
                None,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let error = state
        .call(
            "CreateUser",
            admin.to_string(),
            Command {
                name: "overflow".into(),
                max_duration: 60,
                ..cmd()
            },
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason, "QUEUE_FULL");
    assert_eq!(first.await.unwrap().unwrap_err().reason, "TIMEOUT");
    assert_eq!(second.await.unwrap().unwrap_err().reason, "TIMEOUT");
    blocker.execute_batch("ROLLBACK").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let list = state
        .call("ListUsers", admin.to_string(), cmd(), None)
        .await
        .unwrap();
    assert!(
        list.resources
            .iter()
            .all(|u| u.name != "expired" && u.name != "overflow")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_recovery_and_request_limits() {
    let mut s = Server::new().await;
    s.unlock().await;
    let user = s.user().await;
    let public = easy_sshca::signing::generate("crash")
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    let signed = cli::rpc(
        &user,
        "SignCertificate",
        Command {
            zone: "production".into(),
            public_key: public.clone(),
            ..cmd()
        },
    )
    .await
    .unwrap();
    s.process.kill().unwrap();
    s.process.wait().unwrap();
    s.process = Server::spawn(s.dir.path());
    s.wait().await;
    s.unlock().await;
    let next = cli::rpc(
        &user,
        "SignCertificate",
        Command {
            zone: "production".into(),
            public_key: public,
            ..cmd()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        ssh_key::Certificate::from_openssh(&next.certificate)
            .unwrap()
            .serial(),
        ssh_key::Certificate::from_openssh(&signed.certificate)
            .unwrap()
            .serial()
            + 1
    );
    let oversized = cli::rpc(
        &user,
        "SignCertificate",
        Command {
            public_key: "x".repeat(70000),
            ..cmd()
        },
    )
    .await;
    assert!(oversized.is_err());
    let malformed = cli::rpc(
        &user,
        "SignCertificate",
        Command {
            request_id: "invalid".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    use prost::Message;
    let detail = easy_sshca::protocol::ErrorDetail::decode(
        malformed.downcast_ref::<tonic::Status>().unwrap().details(),
    )
    .unwrap();
    assert_eq!(detail.reason, "INVALID_INPUT");
    auth::request_id(&detail.request_id).unwrap();
    s.stop();
    for entry in std::fs::read_dir(s.dir.path()).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        for secret in [
            &s.secret,
            s.client.api_key.as_ref().unwrap(),
            user.api_key.as_ref().unwrap(),
        ] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "credential leaked into {}",
                entry.path().display()
            );
        }
        assert!(
            !bytes
                .windows(b"OPENSSH PRIVATE KEY".len())
                .any(|w| w == b"OPENSSH PRIVATE KEY")
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_tables_hide_uuids_unless_verbose() {
    let s = Server::new().await;
    s.unlock().await;
    let path = s.dir.path().join("table-admin.yaml");
    config::exclusive(
        &path,
        serde_saphyr::to_string(&s.client).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let human = |args: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
            .arg("--config")
            .arg(&path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(human(&["admin", "zone", "list"]).trim(), "No results.");
    let _user = s.user().await;
    let reply = cli::rpc(&s.client, "ListZones", cmd()).await.unwrap();
    let id = &reply.resources[0].id;
    let table = human(&["admin", "zone", "list"]);
    for value in [
        "Name",
        "Max duration",
        "Status",
        "production",
        "1day",
        "active",
    ] {
        assert!(table.contains(value), "missing {value}: {table}");
    }
    assert!(!table.contains(id));
    assert!(!table.contains("ID"));
    assert!(!table.contains('\t'));
    assert!(human(&["admin", "zone", "list", "--verbose"]).contains(id));
    assert!(human(&["-v", "admin", "zone", "list"]).contains(id));
    let tokens = human(&["admin", "access-token", "list", "--user", "alice"]);
    assert!(tokens.contains("User") && tokens.contains("alice") && tokens.contains("laptop"));
    assert_eq!(
        human(&["admin", "zone", "update", "production", "--active", "false"]).trim(),
        "OK"
    );
    let verbose = human(&[
        "admin",
        "zone",
        "update",
        "production",
        "--active",
        "true",
        "--verbose",
    ]);
    auth::request_id(verbose.trim().strip_prefix("OK ").unwrap()).unwrap();
    let output = run_cli(&path, &["admin", "zone", "list"], None);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["result"]["resources"][0]["id"], *id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_user_zone_commands_grant_list_and_revoke() {
    let s = Server::new().await;
    s.unlock().await;
    let _user = s.user().await;
    let path = s.dir.path().join("zone-admin.yaml");
    config::exclusive(
        &path,
        serde_saphyr::to_string(&s.client).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let run = |args: &[&str]| {
        let output = run_cli(&path, args, None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["result"].clone()
    };
    let listed = run(&["admin", "user", "zone", "list", "alice"]);
    assert_eq!(listed["resources"][0]["name"], "production");
    run(&["admin", "user", "zone", "revoke", "alice", "production"]);
    assert_eq!(
        run(&["admin", "user", "zone", "list", "alice"])["resources"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let empty = std::process::Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .arg("--config")
        .arg(&path)
        .args(["admin", "user", "zone", "list", "alice"])
        .output()
        .unwrap();
    assert!(empty.status.success());
    assert_eq!(
        String::from_utf8(empty.stdout).unwrap().trim(),
        "No results."
    );
    run(&["admin", "user", "zone", "grant", "alice", "production"]);
    let listed = run(&["admin", "user", "zone", "list", "alice", "--page-size", "1"]);
    assert_eq!(listed["resources"][0]["name"], "production");
    assert_eq!(listed["resources"].as_array().unwrap().len(), 1);
    for args in [
        vec!["admin", "user", "grant-zone", "alice", "production"],
        vec!["admin", "user", "revoke-zone", "alice", "production"],
        vec!["admin", "user", "zone", "list", "missing"],
    ] {
        assert!(!run_cli(&path, &args, None).status.success());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exported_token_configs_are_portable_and_support_rotation() {
    use std::os::unix::fs::PermissionsExt;
    let s = Server::new().await;
    s.unlock().await;
    let _user = s.user().await;
    let admin_path = s.dir.path().join("export-admin.yaml");
    config::exclusive(
        &admin_path,
        serde_saphyr::to_string(&s.client).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let portable = tempfile::tempdir().unwrap();
    for (extension, flag) in [("yaml", "-o"), ("json", "--output")] {
        let path = s.dir.path().join(format!("export.{extension}"));
        let output = run_cli(
            &admin_path,
            &[
                "admin",
                "access-token",
                "add",
                "--user",
                "alice",
                "--name",
                extension,
                "--max-duration",
                "30m",
                flag,
                path.to_str().unwrap(),
            ],
            None,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["result"]["config"], path.to_str().unwrap());
        assert_eq!(fs_mode(&path), 0o600);
        let text = std::fs::read_to_string(&path).unwrap();
        if extension == "json" {
            serde_json::from_str::<serde_json::Value>(&text).unwrap();
        }
        let client = ClientConfig::load(&path).unwrap();
        assert!(client.tls_ca.is_none());
        assert!(
            client
                .tls_ca_pem
                .as_ref()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert!(client.defaults.public_key.is_none());
        assert!(client.defaults.zone.is_none());
        assert_eq!(client.defaults.duration.as_deref(), Some("30m"));
        let key = client.api_key.as_ref().unwrap();
        assert!(!String::from_utf8_lossy(&output.stdout).contains(key));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(key));
        assert!(!text.contains(s.client.api_key.as_ref().unwrap()));
        let moved = portable.path().join(format!("client.{extension}"));
        std::fs::rename(&path, &moved).unwrap();
        let moved_client = ClientConfig::load(&moved).unwrap();
        assert!(
            cli::rpc(
                &moved_client,
                "GetPublicKey",
                Command {
                    zone: "production".into(),
                    ..cmd()
                }
            )
            .await
            .is_ok()
        );
        let rotate = run_cli(&moved, &["rotate-token"], None);
        assert!(
            rotate.status.success(),
            "{}",
            String::from_utf8_lossy(&rotate.stderr)
        );
        if extension == "json" {
            serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&moved).unwrap())
                .unwrap();
        }
        let rotated = ClientConfig::load(&moved).unwrap();
        assert_ne!(rotated.api_key, moved_client.api_key);
        assert_eq!(rotated.tls_ca_pem, moved_client.tls_ca_pem);
        assert!(
            cli::rpc(&rotated, "BeginTotpEnrollment", cmd())
                .await
                .is_ok()
        );
        assert!(
            cli::rpc(
                &rotated,
                "GetPublicKey",
                Command {
                    zone: "production".into(),
                    ..cmd()
                }
            )
            .await
            .is_ok()
        );
    }
    fn fs_mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_export_checks_destination_before_creating_credentials() {
    let s = Server::new().await;
    s.unlock().await;
    let _user = s.user().await;
    let admin_path = s.dir.path().join("inline-admin.json");
    let mut inline_admin = s.client.clone();
    inline_admin.tls_ca_pem = inline_admin.tls_pem().unwrap();
    inline_admin.tls_ca = None;
    config::exclusive(
        &admin_path,
        inline_admin.serialize_for(&admin_path).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let destination = s.dir.path().join("existing.yaml");
    config::exclusive(&destination, b"keep this file", 0o600).unwrap();
    let args = [
        "admin",
        "access-token",
        "add",
        "--user",
        "alice",
        "--name",
        "exported",
        "--max-duration",
        "1h",
        "--output",
        destination.to_str().unwrap(),
    ];
    assert!(!run_cli(&admin_path, &args, None).status.success());
    assert_eq!(std::fs::read(&destination).unwrap(), b"keep this file");
    let before = cli::rpc(
        &s.client,
        "ListAccessTokens",
        Command {
            user: "alice".into(),
            ..cmd()
        },
    )
    .await
    .unwrap();
    assert_eq!(before.resources.len(), 1);
    std::fs::remove_file(&destination).unwrap();
    let output = run_cli(&admin_path, &args, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exported = ClientConfig::load(&destination).unwrap();
    assert_eq!(exported.tls_ca_pem, inline_admin.tls_ca_pem);
    assert!(exported.tls_ca.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ca_import_accepts_files_and_stdin_without_logging_keys() {
    let mut s = Server::new().await;
    s.unlock().await;
    let admin = s.dir.path().join("import-admin.yaml");
    config::exclusive(
        &admin,
        serde_saphyr::to_string(&s.client).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let ca = easy_sshca::signing::generate("PRIVATE_KEY_COMMENT_CANARY").unwrap();
    let pem = ca.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let file = s.dir.path().join("existing-ca");
    config::exclusive(&file, pem.as_bytes(), 0o600).unwrap();
    for (name, source, input) in [
        ("from-file", vec!["--file", file.to_str().unwrap()], None),
        ("from-stdin", vec!["--stdin"], Some(pem.as_str())),
        ("from-dash", vec!["--file", "-"], Some(pem.as_str())),
    ] {
        let mut args = vec!["admin", "zone", "import", name];
        args.extend(source);
        let output = run_cli(&admin, &args, input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            reply["result"]["resources"][0]["fingerprint"],
            ca.fingerprint(ssh_key::HashAlg::Sha256).to_string()
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_KEY_COMMENT_CANARY"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_KEY_COMMENT_CANARY"));
    }
    for args in [
        vec!["admin", "zone", "import", "no-source"],
        vec![
            "admin",
            "zone",
            "import",
            "two-sources",
            "--file",
            file.to_str().unwrap(),
            "--stdin",
        ],
        vec![
            "admin",
            "zone",
            "import",
            "missing",
            "--file",
            "/does/not/exist",
        ],
    ] {
        assert!(!run_cli(&admin, &args, None).status.success());
    }
    let bad = run_cli(
        &admin,
        &["admin", "zone", "import", "bad", "--stdin"],
        Some("PRIVATE_INPUT_CANARY"),
    );
    assert!(!bad.status.success());
    assert!(!String::from_utf8_lossy(&bad.stdout).contains("PRIVATE_INPUT_CANARY"));
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("PRIVATE_INPUT_CANARY"));
    for (name, algorithm, password) in [
        ("encrypted", "ed25519", "test-passphrase"),
        ("unsupported", "rsa", ""),
    ] {
        let path = s.dir.path().join(name);
        let generated = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", algorithm, "-N", password, "-f"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(generated.status.success());
        let output = run_cli(
            &admin,
            &[
                "admin",
                "zone",
                "import",
                name,
                "--file",
                path.to_str().unwrap(),
            ],
            None,
        );
        assert!(!output.status.success());
    }
    s.stop();
    let logs = std::fs::read_to_string(s.dir.path().join("server.log")).unwrap();
    assert!(logs.contains("ImportZone"));
    assert!(!logs.contains("PRIVATE_KEY_COMMENT_CANARY"));
    for line in pem
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
    {
        assert!(!logs.contains(line));
    }
}
