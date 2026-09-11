use easy_sshca::protocol::Operation;
use easy_sshca::{auth, config, protocol::Command, signing, storage::Database};
use std::os::unix::fs::PermissionsExt;
use tonic::Code;
fn cmd() -> Command {
    Command {
        request_id: auth::new_id(),
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
        let admin = auth::new_key(auth::KeyKind::Admin).to_string();
        Database::initialize(&path, &secret, &admin, "Example SSH CA").unwrap();
        let mut db = Database::open(&path, &secret).unwrap();
        db.execute(
            Operation::CreateZone,
            &admin,
            &Command {
                name: "production".into(),
                max_duration: 86400,
                ..cmd()
            },
        )
        .unwrap();
        db.execute(
            Operation::CreateUser,
            &admin,
            &Command {
                name: "alice".into(),
                max_duration: 7200,
                ..cmd()
            },
        )
        .unwrap();
        db.execute(
            Operation::GrantZone,
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
                Operation::CreateAccessToken,
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
            Operation::SignCertificate,
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
        assert!(auth::validate_name(input).is_err());
    }
    let key = auth::new_key(auth::KeyKind::AccessToken);
    assert_eq!(
        auth::parse_key(&key).unwrap().kind,
        auth::KeyKind::AccessToken
    );
    assert!(auth::parse_key("esca_at_bad").is_err());
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
    assert_eq!(auth::verify_totp(&secret, "287082", -1, 59).unwrap(), 1);
    assert!(auth::verify_totp(&secret, "287082", 1, 59).is_err());
    assert_eq!(auth::verify_totp(&secret, "287082", -1, 89).unwrap(), 1);
    assert!(auth::verify_totp(&secret, "287082", -1, 90).is_err());
    assert_eq!(
        auth::verify_totp(&secret, "005924", -1, 1234567890).unwrap(),
        41152263
    );
}
#[test]
fn encrypted_restore_wrong_key_and_exclusive_init() {
    let mut f = Fixture::new();
    let key =
        f.db.execute(
            Operation::GetPublicKey,
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
            Operation::GetPublicKey,
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
        db.execute(Operation::ListUsers, &f.admin, &cmd())
            .unwrap()
            .resources[0]
            .name,
        "alice"
    );
    let user_key = signing::generate("restored").unwrap();
    db.execute(
        Operation::SignCertificate,
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
        f.db.execute(Operation::ListUsers, &f.token, &cmd())
            .unwrap_err()
            .code,
        Code::PermissionDenied
    );
    assert_eq!(
        f.db.execute(Operation::BeginTotpEnrollment, &f.admin, &cmd())
            .unwrap_err()
            .code,
        Code::PermissionDenied
    );
    f.db.execute(
        Operation::RevokeZone,
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
        Operation::GrantZone,
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
        Operation::RemoveUser,
        &f.admin,
        &Command {
            name: "alice".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(f.sign("").unwrap_err().code, Code::Unauthenticated);
    let grants: i64 =
        f.db.connection()
            .query_row("SELECT count(*) FROM user_zones", [], |r| r.get(0))
            .unwrap();
    assert_eq!(grants, 0);
}

#[test]
fn removing_a_zone_revokes_access_and_preserves_certificate_history() {
    let mut f = Fixture::new();
    f.sign("").unwrap();

    f.db.execute(
        Operation::RemoveZone,
        &f.admin,
        &Command {
            name: "production".into(),
            ..cmd()
        },
    )
    .unwrap();

    assert!(
        f.db.execute(Operation::ListZones, &f.admin, &cmd())
            .unwrap()
            .resources
            .is_empty()
    );
    assert_eq!(f.sign("").unwrap_err().code, Code::PermissionDenied);
    assert_eq!(
        f.db.execute(
            Operation::GetPublicKey,
            "",
            &Command {
                zone: "production".into(),
                ..cmd()
            },
        )
        .unwrap_err()
        .code,
        Code::NotFound
    );
    assert_eq!(
        f.db.execute(
            Operation::UpdateZone,
            &f.admin,
            &Command {
                name: "production".into(),
                active: Some(true),
                ..cmd()
            },
        )
        .unwrap_err()
        .code,
        Code::NotFound
    );
    let (grants, certificates, removals): (i64, i64, i64) = f
        .db
        .connection()
        .query_row(
            "SELECT (SELECT count(*) FROM user_zones),(SELECT count(*) FROM issued_certificates),(SELECT count(*) FROM zone_removals)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((grants, certificates, removals), (0, 1, 1));
}
#[test]
fn totp_enrollment_replay_and_admin_clear() {
    let mut f = Fixture::new();
    let enrollment =
        f.db.execute(Operation::BeginTotpEnrollment, &f.token, &cmd())
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
        Operation::ConfirmTotpEnrollment,
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
        f.db.execute(Operation::BeginTotpEnrollment, &f.token, &cmd())
            .is_err()
    );
    f.db.execute(
        Operation::ClearTotp,
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
    let replacement = auth::new_key(auth::KeyKind::AccessToken);
    let request = Command {
        replacement_key: replacement.to_string(),
        ..cmd()
    };
    let first =
        f.db.execute(Operation::RotateToken, &f.token, &request)
            .unwrap();
    assert_eq!(
        f.db.execute(Operation::RotateToken, &f.token, &request)
            .unwrap()
            .request_id,
        first.request_id
    );
    assert_eq!(
        f.db.execute(Operation::RotateToken, &replacement, &request)
            .unwrap()
            .request_id,
        first.request_id
    );
    assert!(f.sign("").is_err());
    f.token = replacement.to_string();
    assert!(f.sign("").is_ok());
    let response: Vec<u8> =
        f.db.connection()
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
    let first =
        f.db.execute(Operation::SignCertificate, &f.token, &request)
            .unwrap();
    assert_eq!(
        f.db.execute(Operation::SignCertificate, &f.token, &request)
            .unwrap()
            .certificate,
        first.certificate
    );
    request.duration = 30;
    assert_eq!(
        f.db.execute(Operation::SignCertificate, &f.token, &request)
            .unwrap_err()
            .reason,
        "REQUEST_CONFLICT"
    );
    let serial: i64 =
        f.db.connection()
            .query_row("SELECT next_serial FROM zones", [], |r| r.get(0))
            .unwrap();
    assert_eq!(serial, 2);
    assert!(
        f.db.execute(
            Operation::SignCertificate,
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
        f.db.connection()
            .query_row("SELECT next_serial FROM zones", [], |r| r.get(0))
            .unwrap();
    assert_eq!(after, serial);
    let create = Command {
        user: "alice".into(),
        name: "ci".into(),
        max_duration: 60,
        ..cmd()
    };
    f.db.execute(Operation::CreateAccessToken, &f.admin, &create)
        .unwrap();
    assert_eq!(
        f.db.execute(Operation::CreateAccessToken, &f.admin, &create)
            .unwrap_err()
            .reason,
        "SECRET_ALREADY_DELIVERED"
    );
}
#[test]
fn certificate_retries_require_current_zone_authorization() {
    for revoke_grant in [true, false] {
        let mut f = Fixture::new();
        let request = Command {
            zone: "production".into(),
            public_key: signing::generate("test")
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            ..cmd()
        };
        let first =
            f.db.execute(Operation::SignCertificate, &f.token, &request)
                .unwrap();
        let change = Command {
            user: "alice".into(),
            zone: "production".into(),
            name: "production".into(),
            active: Some(false),
            ..cmd()
        };
        f.db.execute(
            if revoke_grant {
                Operation::RevokeZone
            } else {
                Operation::UpdateZone
            },
            &f.admin,
            &change,
        )
        .unwrap();
        for request_id in [request.request_id.clone(), auth::new_id()] {
            assert_eq!(
                f.db.execute(
                    Operation::SignCertificate,
                    &f.token,
                    &Command {
                        request_id,
                        ..request.clone()
                    },
                )
                .unwrap_err()
                .code,
                Code::PermissionDenied
            );
        }
        f.db.execute(
            if revoke_grant {
                Operation::GrantZone
            } else {
                Operation::UpdateZone
            },
            &f.admin,
            &Command {
                request_id: auth::new_id(),
                active: Some(true),
                ..change
            },
        )
        .unwrap();
        assert_eq!(
            f.db.execute(Operation::SignCertificate, &f.token, &request)
                .unwrap(),
            first
        );
        assert_eq!(f.db.issuance_count, 1);
        let (serial, issued): (u64, u64) = f.db.connection().query_row(
            "SELECT next_serial,(SELECT count(*) FROM issued_certificates) FROM zones WHERE name='production'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!((serial, issued), (2, 1));
    }
}

#[test]
fn certificate_retries_accept_consumed_totp() {
    let mut f = Fixture::new();
    let secret = auth::totp_secret();
    f.db.connection()
        .execute(
            "UPDATE users SET totp_secret=?1,last_step=-1 WHERE name='alice'",
            [&*secret],
        )
        .unwrap();
    let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).unwrap();
    let request = Command {
        zone: "production".into(),
        public_key: signing::generate("test")
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        totp: totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &bytes, auth::now()),
        ..cmd()
    };
    let first =
        f.db.execute(Operation::SignCertificate, &f.token, &request)
            .unwrap();
    assert_eq!(
        f.db.execute(Operation::SignCertificate, &f.token, &request)
            .unwrap(),
        first
    );
    assert_eq!(
        f.db.execute(
            Operation::SignCertificate,
            &f.token,
            &Command {
                request_id: auth::new_id(),
                ..request
            }
        )
        .unwrap_err()
        .reason,
        "INVALID_TOTP"
    );
    assert_eq!(f.db.issuance_count, 1);
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
        Operation::CreateUser,
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
            Operation::ListUsers,
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
            Operation::ListUsers,
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
        Operation::UpdateAccessToken,
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
    f.db.execute(Operation::BeginTotpEnrollment, &f.token, &cmd())
        .unwrap();
    f.db.connection()
        .execute("UPDATE users SET pending_expires=0", [])
        .unwrap();
    assert_eq!(
        f.db.execute(
            Operation::ConfirmTotpEnrollment,
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
    let replacement = auth::new_key(auth::KeyKind::Admin);
    f.db.reset_admin(&replacement).unwrap();
    assert!(
        f.db.execute(Operation::ListUsers, &f.admin, &cmd())
            .is_err()
    );
    assert!(
        f.db.execute(Operation::ListUsers, &replacement, &cmd())
            .is_ok()
    );
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
            Operation::CreateZone,
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
        Operation::GrantZone,
        &f.admin,
        &Command {
            user: "alice".into(),
            zone: "staging".into(),
            ..cmd()
        },
    )
    .unwrap();
    f.db.execute(
        Operation::UpdateZone,
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
    let first =
        f.db.execute(Operation::ListUserZones, &f.admin, &query)
            .unwrap();
    assert_eq!(first.resources.len(), 1);
    assert_eq!(first.resources[0].name, "production");
    assert!(!first.resources[0].active);
    assert!(!first.next_page_token.is_empty());
    let next =
        f.db.execute(
            Operation::ListUserZones,
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
        Operation::CreateUser,
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
            Operation::ListUserZones,
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
            Operation::ListUserZones,
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
        f.db.execute(Operation::ListUserZones, &f.token, &query)
            .unwrap_err()
            .code,
        Code::PermissionDenied
    );
    assert_eq!(
        f.db.execute(
            Operation::ListUserZones,
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
        Operation::RemoveUser,
        &f.admin,
        &Command {
            name: "alice".into(),
            ..cmd()
        },
    )
    .unwrap();
    assert_eq!(
        f.db.execute(Operation::ListUserZones, &f.admin, &query)
            .unwrap_err()
            .code,
        Code::NotFound
    );
}

#[test]
fn client_config_accepts_inline_tls_and_rejects_ambiguous_trust() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .unwrap()
        .cert
        .pem();
    let mut client = config::ClientConfig {
        version: 1,
        server: "https://localhost:9443".into(),
        api_key: None,
        api_key_file: None,
        bootstrap_secret: None,
        bootstrap_secret_file: None,
        tls_ca: None,
        tls_ca_pem: Some(cert.clone()),
        tls_server_name: None,
        defaults: Default::default(),
    };
    for extension in ["yaml", "json"] {
        let path = dir.path().join(format!("client.{extension}"));
        config::exclusive(
            &path,
            client.serialize_for(&path).unwrap().as_bytes(),
            0o600,
        )
        .unwrap();
        assert_eq!(
            config::ClientConfig::load(&path)
                .unwrap()
                .tls_pem()
                .unwrap(),
            Some(cert.clone())
        );
    }
    client.tls_ca = Some("missing.pem".into());
    assert!(
        client
            .validate()
            .unwrap_err()
            .to_string()
            .contains("only one")
    );
    client.tls_ca = None;
    client.tls_ca_pem = Some(String::new());
    assert!(client.validate().is_err());
    client.tls_ca_pem = None;
    assert_eq!(client.tls_pem().unwrap(), None);
    let path = dir.path().join("invalid.json");
    config::exclusive(&path, br#"{"version": 1, "server": "https://localhost:9443", "api_key": "SECRET_CANARY", "unknown": 1}"#, 0o600).unwrap();
    let error = config::ClientConfig::load(&path).err().unwrap().to_string();
    assert!(!error.contains("SECRET_CANARY"));
}

#[test]
fn configs_accept_inline_and_external_secret_sources() {
    let dir = tempfile::tempdir().unwrap();
    let api_key = auth::new_key(auth::KeyKind::Admin);
    let bootstrap_secret = auth::random_secret();
    config::exclusive(
        &dir.path().join("api-key"),
        format!("{}\n", api_key.as_str()).as_bytes(),
        0o600,
    )
    .unwrap();
    config::exclusive(
        &dir.path().join("bootstrap-secret"),
        format!("{}\n", bootstrap_secret.as_str()).as_bytes(),
        0o600,
    )
    .unwrap();
    let path = dir.path().join("client.yaml");
    config::exclusive(
        &path,
        b"version: 1\nserver: https://localhost:9443\napi_key_file: api-key\nbootstrap_secret_file: bootstrap-secret\n",
        0o600,
    )
    .unwrap();
    let client = config::ClientConfig::load(&path).unwrap();
    assert_eq!(
        client.api_key_value().unwrap().unwrap().as_str(),
        api_key.as_str()
    );
    assert_eq!(
        client.bootstrap_secret_value().unwrap().unwrap().as_str(),
        bootstrap_secret.as_str()
    );

    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_path = dir.path().join("server.yaml");
    let server = config::ServerConfig {
        server: config::default_server(),
        version: 1,
        database: "ca.db".into(),
        rpc_listen: "127.0.0.1:9443".parse().unwrap(),
        https_listen: "127.0.0.1:9444".parse().unwrap(),
        metrics_listen: None,
        tls: config::Tls {
            certificate: None,
            certificate_pem: Some(tls.cert.pem()),
            private_key: None,
            private_key_pem: Some(tls.signing_key.serialize_pem()),
        },
        limits: config::Limits {
            request_bytes: 65536,
            rpc_timeout: "10s".into(),
            database_queue: 128,
        },
    };
    config::exclusive(
        &server_path,
        serde_saphyr::to_string(&server).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let loaded = config::ServerConfig::load(&server_path).unwrap();
    assert_eq!(loaded.certificate_pem().unwrap(), tls.cert.pem().as_bytes());
    assert_eq!(
        loaded.private_key_pem().unwrap().as_str(),
        tls.signing_key.serialize_pem()
    );
}

#[test]
fn imported_ca_preserves_identity_signs_and_survives_restart() {
    let mut f = Fixture::new();
    let ca = signing::generate("existing CA").unwrap();
    let pem = ca.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let import = Command {
        name: "imported".into(),
        secret: pem.to_string(),
        max_duration: 3600,
        ..cmd()
    };
    let result =
        f.db.execute(Operation::ImportZone, &f.admin, &import)
            .unwrap();
    assert_eq!(
        result.resources[0].fingerprint,
        ca.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    );
    assert_eq!(
        f.db.execute(Operation::ImportZone, &f.admin, &import)
            .unwrap(),
        result
    );
    let mut duplicate = import.clone();
    duplicate.request_id = auth::new_id();
    duplicate.secret = signing::generate("different")
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    assert_eq!(
        f.db.execute(Operation::ImportZone, &f.admin, &duplicate)
            .unwrap_err()
            .code,
        Code::AlreadyExists
    );
    let public =
        f.db.execute(
            Operation::GetPublicKey,
            "",
            &Command {
                zone: "imported".into(),
                ..cmd()
            },
        )
        .unwrap();
    assert_eq!(public.fingerprint, result.resources[0].fingerprint);
    f.db.execute(
        Operation::GrantZone,
        &f.admin,
        &Command {
            user: "alice".into(),
            zone: "imported".into(),
            ..cmd()
        },
    )
    .unwrap();
    let signing_request = Command {
        zone: "imported".into(),
        public_key: signing::generate("user")
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        duration: 60,
        ..cmd()
    };
    let signed =
        f.db.execute(Operation::SignCertificate, &f.token, &signing_request)
            .unwrap();
    let certificate = ssh_key::Certificate::from_openssh(&signed.certificate).unwrap();
    certificate
        .validate_at(auth::now(), [&ca.fingerprint(ssh_key::HashAlg::Sha256)])
        .unwrap();
    drop(f.db);
    let mut db = Database::open(&f.dir.path().join("ca.db"), &f.secret).unwrap();
    let signed = db
        .execute(
            Operation::SignCertificate,
            &f.token,
            &Command {
                request_id: auth::new_id(),
                ..signing_request
            },
        )
        .unwrap();
    ssh_key::Certificate::from_openssh(&signed.certificate)
        .unwrap()
        .validate_at(auth::now(), [&ca.fingerprint(ssh_key::HashAlg::Sha256)])
        .unwrap();
    let disk = std::fs::read(f.dir.path().join("ca.db")).unwrap();
    for line in pem
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
    {
        assert!(
            !disk
                .windows(line.len())
                .any(|window| window == line.as_bytes())
        );
    }
}

#[test]
fn invalid_imports_do_not_create_zones() {
    let mut f = Fixture::new();
    for secret in [
        "not a private key".to_string(),
        "x".repeat(4097),
        signing::generate("public only")
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
    ] {
        let result = f.db.execute(
            Operation::ImportZone,
            &f.admin,
            &Command {
                name: "invalid".into(),
                max_duration: 60,
                secret,
                ..cmd()
            },
        );
        assert_eq!(result.unwrap_err().code, Code::InvalidArgument);
    }
    let zones =
        f.db.execute(Operation::ListZones, &f.admin, &cmd())
            .unwrap();
    assert_eq!(zones.resources.len(), 1);
    assert_eq!(zones.resources[0].name, "production");
}

#[test]
fn duplicate_ca_imports_are_atomic_and_ignore_comments_and_zone_state() {
    let mut f = Fixture::new();
    let pem: String =
        f.db.connection()
            .query_row(
                "SELECT private_key FROM zones WHERE name='production'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    let mut ca = signing::import(&pem).unwrap();
    for active in [true, false] {
        f.db.execute(
            Operation::UpdateZone,
            &f.admin,
            &Command {
                name: "production".into(),
                active: Some(active),
                ..cmd()
            },
        )
        .unwrap();
        for comment in ["production", "different comment"] {
            ca.set_comment(comment);
            let request = Command {
                name: "restricted".into(),
                secret: ca
                    .to_openssh(ssh_key::LineEnding::CRLF)
                    .unwrap()
                    .to_string(),
                max_duration: 60,
                ..cmd()
            };
            let error =
                f.db.execute(Operation::ImportZone, &f.admin, &request)
                    .unwrap_err();
            assert_eq!(error.code, Code::AlreadyExists);
            assert_eq!(error.reason, "DUPLICATE_CA");
            let saved: u64 =
                f.db.connection()
                    .query_row(
                        "SELECT count(*) FROM idempotency_records WHERE request_id=?1",
                        [&request.request_id],
                        |r| r.get(0),
                    )
                    .unwrap();
            assert_eq!(saved, 0);
        }
    }
    assert_eq!(
        f.db.execute(Operation::ListZones, &f.admin, &cmd())
            .unwrap()
            .resources
            .len(),
        1
    );
    f.db.execute(
        Operation::ImportZone,
        &f.admin,
        &Command {
            name: "restricted".into(),
            secret: signing::generate("fresh CA")
                .unwrap()
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            max_duration: 60,
            ..cmd()
        },
    )
    .unwrap();
}

fn assert_ca_indexes(db: &Database) {
    for column in ["fingerprint", "public_key"] {
        let sql = format!(
            "INSERT INTO zones SELECT 'duplicate','duplicate',private_key,{}, {},max_duration,1,0,created_at,updated_at FROM zones WHERE name='production'",
            if column == "public_key" {
                "public_key"
            } else {
                "'different public key'"
            },
            if column == "fingerprint" {
                "fingerprint"
            } else {
                "'different fingerprint'"
            }
        );
        let error = db.connection().execute(&sql, []).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        );
    }
}

#[test]
fn ca_uniqueness_is_enforced_on_new_and_existing_databases() {
    let f = Fixture::new();
    assert_ca_indexes(&f.db);
    f.db.connection()
        .execute_batch("DROP INDEX zone_ca_public_key; DROP INDEX zone_ca_fingerprint;")
        .unwrap();
    drop(f.db);
    for _ in 0..2 {
        let db = Database::open(&f.dir.path().join("ca.db"), &f.secret).unwrap();
        assert_ca_indexes(&db);
    }
}

#[test]
fn existing_duplicate_ca_keys_prevent_unlock_without_partial_migration() {
    let f = Fixture::new();
    f.db.connection()
        .execute_batch("DROP INDEX zone_ca_public_key; DROP INDEX zone_ca_fingerprint;")
        .unwrap();
    f.db.connection().execute(
        "INSERT INTO zones SELECT 'duplicate','restricted',private_key,public_key,fingerprint,max_duration,1,0,created_at,updated_at FROM zones WHERE name='production'", [],
    ).unwrap();
    drop(f.db);
    let path = f.dir.path().join("ca.db");
    let before = std::fs::read(&path).unwrap();
    let error = Database::open(&path, &f.secret).err().unwrap();
    assert_eq!(error.code, Code::FailedPrecondition);
    assert_eq!(error.reason, "DUPLICATE_CA");
    assert!(error.message.contains("production"));
    assert!(error.message.contains("restricted"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn tls_server_name_config_validation_and_round_trip() {
    let base = r#"{"version":1,"server":"https://localhost:9443"}"#;
    let mut config: config::ClientConfig = serde_json::from_str(base).unwrap();
    assert!(config.tls_server_name.is_none());
    for name in ["ca.example", "127.0.0.1", "::1"] {
        config.tls_server_name = Some(name.into());
        config.validate().unwrap();
        let text = serde_json::to_string(&config).unwrap();
        let restored: config::ClientConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(restored.tls_server_name.as_deref(), Some(name));
    }
    for name in ["", "https://ca.example", "ca.example:9443", "a b"] {
        config.tls_server_name = Some(name.into());
        assert!(config.validate().is_err());
    }
}

#[test]
fn failed_auth_is_audited_and_oldest_events_are_evicted() {
    let mut f = Fixture::new();
    f.db.connection()
        .execute("DELETE FROM audit_events", [])
        .unwrap();
    f.db.connection().execute("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) INSERT INTO audit_events SELECT CAST(x AS TEXT),'','','seed','OK',CAST(x AS TEXT),0 FROM n", []).unwrap();
    let malformed = cmd();
    assert!(
        f.db.execute(Operation::ListZones, "not-a-key", &malformed)
            .is_err()
    );
    let row: (String, String, String) =
        f.db.connection()
            .query_row(
                "SELECT actor_type,actor_id,result FROM audit_events WHERE request_id=?1",
                [&malformed.request_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!(
        row,
        (String::new(), String::new(), "MALFORMED_CREDENTIAL".into())
    );
    let invalid = auth::new_key(auth::KeyKind::Admin);
    for _ in 0..50 {
        assert!(
            f.db.execute(Operation::ListZones, &invalid, &cmd())
                .is_err()
        );
    }
    let count: i64 =
        f.db.connection()
            .query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 10000);
    let oldest: String =
        f.db.connection()
            .query_row(
                "SELECT id FROM audit_events ORDER BY rowid LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(oldest, "52");
    f.db.connection()
        .execute(
            "INSERT INTO audit_events VALUES('extra','','','seed','OK','extra',0)",
            [],
        )
        .unwrap();
    let path = f.dir.path().join("ca.db");
    drop(f.db);
    let db = Database::open(&path, &f.secret).unwrap();
    let count: i64 = db
        .connection()
        .query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 10000);
}
