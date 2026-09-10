use easy_sshca::{auth, config, protocol::Command, signing, storage::Database};
use std::os::unix::fs::PermissionsExt;
use tonic::Code;
fn cmd() -> Command {
    Command {
        request_id: auth::id(),
        ..Default::default()
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    secret: String,
    admin: String,
    db: Database,
    token: String,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.db");
        let secret = auth::random_secret().to_string();
        let admin = auth::new_key("ad").to_string();
        Database::initialize(&path, &secret, &admin, "Example SSH CA").unwrap();
        let mut db = Database::open(&path, &secret).unwrap();
        db.execute(
            "CreateZone",
            &admin,
            &Command {
                name: "production".into(),
                max_duration: 86400,
                ..cmd()
            },
        )
        .unwrap();
        db.execute(
            "CreateUser",
            &admin,
            &Command {
                name: "alice".into(),
                max_duration: 7200,
                ..cmd()
            },
        )
        .unwrap();
        db.execute(
            "GrantZone",
            &admin,
            &Command {
                user: "alice".into(),
                zone: "production".into(),
                ..cmd()
            },
        )
        .unwrap();
        let token = db
            .execute(
                "CreateAccessToken",
                &admin,
                &Command {
                    user: "alice".into(),
                    name: "laptop".into(),
                    max_duration: 3600,
                    ..cmd()
                },
            )
            .unwrap()
            .api_key;
        Self {
            dir,
            secret,
            admin,
            db,
            token,
        }
    }
    fn sign(&mut self, code: &str) -> easy_sshca::error::Result<easy_sshca::protocol::Reply> {
        let key = signing::generate("test").unwrap();
        self.db.execute(
            "SignCertificate",
            &self.token,
            &Command {
                zone: "production".into(),
                public_key: key.public_key().to_openssh().unwrap(),
                totp: code.into(),
                duration: 86400,
                ..cmd()
            },
        )
    }
}
#[test]
fn durations_names_credentials_and_redaction() {
    for (input, seconds) in [("30m", 1800), ("12h", 43200), ("1d", 86400), ("1w", 604800)] {
        assert_eq!(auth::parse_duration(input).unwrap(), seconds);
    }
    for input in ["0s", "-1h", "1ms", "400d", "garbage"] {
        assert!(auth::parse_duration(input).is_err());
    }
    for input in ["", "../etc/passwd", "üser", "a b"] {
        assert!(auth::name(input).is_err());
    }
    let key = auth::new_key("at");
    assert_eq!(auth::key(&key).unwrap().kind, "at");
    assert!(auth::key("esca_at_bad").is_err());
    assert!(
        !format!(
            "{:?}",
            Command {
                secret: key.to_string(),
                ..cmd()
            }
        )
        .contains(&*key)
    );
}
#[test]
fn rfc_totp_window_zero_padding_and_replay() {
    let secret = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        b"12345678901234567890",
    );
    assert_eq!(auth::totp_step(&secret, "287082", -1, 59).unwrap(), 1);
    assert!(auth::totp_step(&secret, "287082", 1, 59).is_err());
    assert_eq!(auth::totp_step(&secret, "287082", -1, 89).unwrap(), 1);
    assert!(auth::totp_step(&secret, "287082", -1, 90).is_err());
    assert_eq!(
        auth::totp_step(&secret, "005924", -1, 1234567890).unwrap(),
        41152263
    );
}
#[test]
fn encrypted_restore_wrong_key_and_exclusive_init() {
    let mut f = Fixture::new();
    let key =
        f.db.execute(
            "GetPublicKey",
            "",
            &Command {
                zone: "production".into(),
                ..cmd()
            },
        )
        .unwrap();
    let path = f.dir.path().join("ca.db");
    assert!(Database::initialize(&path, &f.secret, &f.admin, "other").is_err());
    assert!(Database::open(&path, &f.secret).is_err());
    drop(f.db);
    let data = std::fs::read(&path).unwrap();
    assert!(!data.starts_with(b"SQLite format 3"));
    for secret in [&f.admin, &f.token, &f.secret, &key.public_key] {
        assert!(!data.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
    assert!(Database::open(&path, &auth::random_secret()).is_err());
    let backup = f.dir.path().join("restore.db");
    std::fs::copy(path, &backup).unwrap();
    let mut db = Database::open(&backup, &f.secret).unwrap();
    assert_eq!(
        db.execute(
            "GetPublicKey",
            "",
            &Command {
                zone: "production".into(),
                ..cmd()
            }
        )
        .unwrap()
        .fingerprint,
        key.fingerprint
    );
    assert_eq!(
        db.execute("ListUsers", &f.admin, &cmd()).unwrap().resources[0].name,
        "alice"
    );
    let user_key = signing::generate("restored").unwrap();
    db.execute(
        "SignCertificate",
        &f.token,
        &Command {
            zone: "production".into(),
            public_key: user_key.public_key().to_openssh().unwrap(),
            ..cmd()
        },
    )
    .unwrap();
}
#[test]
fn certificates_are_owned_clamped_and_openssh_compatible() {
    let mut f = Fixture::new();
    let reply = f.sign("").unwrap();
    assert_eq!(reply.effective_duration, 3600);
    let cert = ssh_key::Certificate::from_openssh(&reply.certificate).unwrap();
    assert_eq!(cert.valid_principals(), ["alice"]);
    assert_eq!(cert.serial(), 1);
    assert_eq!(cert.extensions().len(), 5);
    assert_eq!(cert.valid_before() - cert.valid_after(), 3900);
    let file = f.dir.path().join("certificate.pub");
    std::fs::write(&file, reply.certificate).unwrap();
    let output = std::process::Command::new("ssh-keygen")
        .arg("-Lf")
        .arg(&file)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("alice"));
    assert_eq!(
        ssh_key::Certificate::from_openssh(&f.sign("").unwrap().certificate)
            .unwrap()
            .serial(),
        2
    );
}
#[test]
fn admin_boundaries_grants_and_removal() {
    let mut f = Fixture::new();
    assert_eq!(
        f.db.execute("ListUsers", &f.token, &cmd())
            .unwrap_err()
            .code,
        Code::PermissionDenied
    );
    assert_eq!(
        f.db.execute("BeginTotpEnrollment", &f.admin, &cmd())
            .unwrap_err()
            .code,
        Code::PermissionDenied
    );
    f.db.execute(
        "RevokeZone",
        &f.admin,
        &Command {
            user: "alice".into(),
            zone: "production".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(f.sign("").unwrap_err().code, Code::PermissionDenied);
    f.db.execute(
        "GrantZone",
        &f.admin,
        &Command {
            user: "alice".into(),
            zone: "production".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert!(f.sign("").is_ok());
    f.db.execute(
        "RemoveUser",
        &f.admin,
        &Command {
            name: "alice".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(f.sign("").unwrap_err().code, Code::Unauthenticated);
    let grants: i64 =
        f.db.connection
            .query_row("SELECT count(*) FROM user_zones", [], |r| r.get(0))
            .unwrap();
    assert_eq!(grants, 0);
}
#[test]
fn totp_enrollment_replay_and_admin_clear() {
    let mut f = Fixture::new();
    let enrollment =
        f.db.execute("BeginTotpEnrollment", &f.token, &cmd())
            .unwrap();
    assert!(enrollment.otpauth_uri.contains("issuer=Example+SSH+CA"));
    let bytes = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &enrollment.secret,
    )
    .unwrap();
    let now = auth::now();
    let code = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &bytes, now);
    f.db.execute(
        "ConfirmTotpEnrollment",
        &f.token,
        &Command {
            totp: code.clone(),
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(f.sign("").unwrap_err().reason, "TOTP_REQUIRED");
    assert_eq!(f.sign(&code).unwrap_err().reason, "INVALID_TOTP");
    let next = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &bytes, now + 30);
    assert!(f.sign(&next).is_ok());
    assert!(f.sign(&next).is_err());
    assert!(
        f.db.execute("BeginTotpEnrollment", &f.token, &cmd())
            .is_err()
    );
    f.db.execute(
        "ClearTotp",
        &f.admin,
        &Command {
            user: "alice".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert!(f.sign("").is_ok());
}
#[test]
fn token_rotation_retries_do_not_store_plaintext() {
    let mut f = Fixture::new();
    let replacement = auth::new_key("at");
    let request = Command {
        replacement_key: replacement.to_string(),
        ..cmd()
    };
    let first = f.db.execute("RotateToken", &f.token, &request).unwrap();
    assert_eq!(
        f.db.execute("RotateToken", &f.token, &request)
            .unwrap()
            .request_id,
        first.request_id
    );
    assert_eq!(
        f.db.execute("RotateToken", &replacement, &request)
            .unwrap()
            .request_id,
        first.request_id
    );
    assert!(f.sign("").is_err());
    f.token = replacement.to_string();
    assert!(f.sign("").is_ok());
    let response: Vec<u8> =
        f.db.connection
            .query_row(
                "SELECT response FROM idempotency_records WHERE request_id=?1",
                [request.request_id],
                |r| r.get(0),
            )
            .unwrap();
    assert!(
        !response
            .windows(replacement.len())
            .any(|w| w == replacement.as_bytes())
    );
}
#[test]
fn idempotency_conflicts_secret_replays_and_failed_sign_rollback() {
    let mut f = Fixture::new();
    let key = signing::generate("test").unwrap();
    let mut request = Command {
        public_key: key.public_key().to_openssh().unwrap(),
        zone: "production".into(),
        ..cmd()
    };
    let first = f.db.execute("SignCertificate", &f.token, &request).unwrap();
    assert_eq!(
        f.db.execute("SignCertificate", &f.token, &request)
            .unwrap()
            .certificate,
        first.certificate
    );
    request.duration = 30;
    assert_eq!(
        f.db.execute("SignCertificate", &f.token, &request)
            .unwrap_err()
            .reason,
        "REQUEST_CONFLICT"
    );
    let serial: i64 =
        f.db.connection
            .query_row("SELECT next_serial FROM zones", [], |r| r.get(0))
            .unwrap();
    assert_eq!(serial, 2);
    assert!(
        f.db.execute(
            "SignCertificate",
            &f.token,
            &Command {
                zone: "production".into(),
                public_key: "bad".into(),
                ..cmd()
            }
        )
        .is_err()
    );
    let after: i64 =
        f.db.connection
            .query_row("SELECT next_serial FROM zones", [], |r| r.get(0))
            .unwrap();
    assert_eq!(after, serial);
    let create = Command {
        user: "alice".into(),
        name: "ci".into(),
        max_duration: 60,
        ..cmd()
    };
    f.db.execute("CreateAccessToken", &f.admin, &create)
        .unwrap();
    assert_eq!(
        f.db.execute("CreateAccessToken", &f.admin, &create)
            .unwrap_err()
            .reason,
        "SECRET_ALREADY_DELIVERED"
    );
}
#[test]
fn strict_yaml_permissions_paths_and_key_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let good = "version: 1\nserver: https://localhost:9443\ndefaults:\n  public_key: key.pub\n  duration: 1h\n";
    config::exclusive(&path, good.as_bytes(), 0o600).unwrap();
    assert_eq!(
        config::ClientConfig::load(&path)
            .unwrap()
            .defaults
            .public_key,
        Some(dir.path().join("key.pub"))
    );
    for value in [
        good.replace("version: 1", "version: 2"),
        format!("{good}unknown: true\n"),
        format!("{good}server: https://other\n"),
        good.replace("https:", "http:"),
    ] {
        std::fs::write(&path, value).unwrap();
        assert!(config::ClientConfig::load(&path).is_err());
    }
    std::fs::write(&path, good).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(config::ClientConfig::load(&path).is_err());
    std::fs::write(dir.path().join("id_ed25519-cert.pub"), "").unwrap();
    assert!(easy_sshca::cli::discover_key(dir.path()).is_err());
    std::fs::write(dir.path().join("id_ed25519.pub"), "").unwrap();
    assert!(easy_sshca::cli::discover_key(dir.path()).is_ok());
    std::fs::write(dir.path().join("id_rsa.pub"), "").unwrap();
    assert!(easy_sshca::cli::discover_key(dir.path()).is_err());
}
#[test]
fn pagination_updates_expired_enrollment_and_offline_reset() {
    let mut f = Fixture::new();
    f.db.execute(
        "CreateUser",
        &f.admin,
        &Command {
            name: "bob".into(),
            max_duration: 60,
            ..cmd()
        },
    )
    .unwrap();
    let page =
        f.db.execute(
            "ListUsers",
            &f.admin,
            &Command {
                page_size: 1,
                ..cmd()
            },
        )
        .unwrap();
    assert_eq!(page.resources.len(), 1);
    assert!(!page.next_page_token.is_empty());
    let next =
        f.db.execute(
            "ListUsers",
            &f.admin,
            &Command {
                page_token: page.next_page_token,
                page_size: 1,
                ..cmd()
            },
        )
        .unwrap();
    assert_eq!(next.resources[0].name, "bob");
    f.db.execute(
        "UpdateAccessToken",
        &f.admin,
        &Command {
            user: "alice".into(),
            name: "laptop".into(),
            max_duration: 30,
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(f.sign("").unwrap().effective_duration, 30);
    f.db.execute("BeginTotpEnrollment", &f.token, &cmd())
        .unwrap();
    f.db.connection
        .execute("UPDATE users SET pending_expires=0", [])
        .unwrap();
    assert_eq!(
        f.db.execute(
            "ConfirmTotpEnrollment",
            &f.token,
            &Command {
                totp: "000000".into(),
                ..cmd()
            }
        )
        .unwrap_err()
        .reason,
        "ENROLLMENT_EXPIRED"
    );
    let replacement = auth::new_key("ad");
    f.db.reset_admin(&replacement).unwrap();
    assert!(f.db.execute("ListUsers", &f.admin, &cmd()).is_err());
    assert!(f.db.execute("ListUsers", &replacement, &cmd()).is_ok());
}

#[test]
fn relative_configuration_paths_survive_atomic_rewrites() {
    let dir = tempfile::tempdir_in(".").unwrap();
    let path = dir.path().join("client.yaml");
    std::fs::write(dir.path().join("root.pem"), "test trust file").unwrap();
    config::exclusive(&path, b"version: 1\nserver: https://localhost:9443\ntls_ca: root.pem\ndefaults:\n  public_key: key.pub\n", 0o600).unwrap();
    let original = config::ClientConfig::load(&path).unwrap();
    assert!(original.tls_ca.as_ref().unwrap().is_absolute());
    assert!(original.defaults.public_key.as_ref().unwrap().is_absolute());
    config::atomic(
        &path,
        serde_saphyr::to_string(&original).unwrap().as_bytes(),
    )
    .unwrap();
    let rewritten = config::ClientConfig::load(&path).unwrap();
    assert_eq!(rewritten.tls_ca, original.tls_ca);
    assert_eq!(rewritten.defaults.public_key, original.defaults.public_key);
}

#[test]
fn user_zone_listing_is_scoped_and_paginated() {
    let mut f = Fixture::new();
    for name in ["staging", "ungranted"] {
        f.db.execute(
            "CreateZone",
            &f.admin,
            &Command {
                name: name.into(),
                max_duration: 3600,
                ..cmd()
            },
        )
        .unwrap();
    }
    f.db.execute(
        "GrantZone",
        &f.admin,
        &Command {
            user: "alice".into(),
            zone: "staging".into(),
            ..cmd()
        },
    )
    .unwrap();
    f.db.execute(
        "UpdateZone",
        &f.admin,
        &Command {
            name: "production".into(),
            active: Some(false),
            ..cmd()
        },
    )
    .unwrap();
    let query = Command {
        user: "alice".into(),
        page_size: 1,
        ..cmd()
    };
    let first = f.db.execute("ListUserZones", &f.admin, &query).unwrap();
    assert_eq!(first.resources.len(), 1);
    assert_eq!(first.resources[0].name, "production");
    assert!(!first.resources[0].active);
    assert!(!first.next_page_token.is_empty());
    let next =
        f.db.execute(
            "ListUserZones",
            &f.admin,
            &Command {
                page_token: first.next_page_token.clone(),
                ..query.clone()
            },
        )
        .unwrap();
    assert_eq!(next.resources.len(), 1);
    assert_eq!(next.resources[0].name, "staging");
    assert!(next.next_page_token.is_empty());
    f.db.execute(
        "CreateUser",
        &f.admin,
        &Command {
            name: "bob".into(),
            max_duration: 3600,
            ..cmd()
        },
    )
    .unwrap();
    assert!(
        f.db.execute(
            "ListUserZones",
            &f.admin,
            &Command {
                user: "bob".into(),
                ..cmd()
            }
        )
        .unwrap()
        .resources
        .is_empty()
    );
    assert_eq!(
        f.db.execute(
            "ListUserZones",
            &f.admin,
            &Command {
                user: "bob".into(),
                page_token: first.next_page_token,
                ..cmd()
            }
        )
        .unwrap_err()
        .code,
        Code::InvalidArgument
    );
    assert_eq!(
        f.db.execute("ListUserZones", &f.token, &query)
            .unwrap_err()
            .code,
        Code::PermissionDenied
    );
    assert_eq!(
        f.db.execute(
            "ListUserZones",
            &f.admin,
            &Command {
                user: "missing".into(),
                ..cmd()
            }
        )
        .unwrap_err()
        .code,
        Code::NotFound
    );
    f.db.execute(
        "RemoveUser",
        &f.admin,
        &Command {
            name: "alice".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(
        f.db.execute("ListUserZones", &f.admin, &query)
            .unwrap_err()
            .code,
        Code::NotFound
    );
}
