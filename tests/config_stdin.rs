use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn run(args: &[&str], input: &[u8]) -> (Output, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .args(args)
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input);
    (child.wait_with_output().unwrap(), dir)
}

#[test]
fn yaml_and_json_stdin_resolve_relative_paths() {
    for input in [
        "version: 1\nserver: https://localhost:9443\napi_key_file: missing-key\n",
        r#"{"version":1,"server":"https://localhost:9443","api_key_file":"missing-key"}"#,
    ] {
        let (output, dir) = run(&["server", "status", "--config", "-"], input.as_bytes());
        let error = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{error}");
        assert!(
            error.contains(dir.path().join("missing-key").to_str().unwrap()),
            "{error}"
        );
        assert!(!dir.path().join("-").exists());
    }
}

#[test]
fn stdin_rejects_invalid_empty_and_oversized_configs_without_echoing_secrets() {
    for input in [
        Vec::new(),
        b"version: SECRET_MARKER\nserver: https://localhost\n".to_vec(),
        vec![b'x'; 1024 * 1024 + 1],
    ] {
        let (output, _) = run(&["--config", "-", "server", "status"], &input);
        let error = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{error}");
        assert!(!error.contains("SECRET_MARKER"));
        assert!(
            error.contains(if input.len() > 1024 * 1024 {
                "1 MiB"
            } else {
                "invalid client YAML"
            }),
            "{error}"
        );
    }
}

#[test]
fn stdin_conflicts_and_config_writes_fail_before_reading() {
    for args in [
        vec!["sign", "--totp-stdin"],
        vec!["totp", "confirm", "--totp-stdin"],
        vec!["server", "unlock", "--secret-stdin"],
        vec!["admin", "zone", "import", "zone", "--stdin"],
        vec!["admin", "zone", "import", "zone", "--file", "-"],
        vec!["configure", "--server", "https://localhost"],
        vec!["rotate-token"],
        vec!["admin", "key", "rotate-admin"],
    ] {
        let mut command = vec!["--config", "-"];
        command.extend(args);
        let (output, dir) = run(&command, b"");
        let error = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{command:?}: {error}");
        assert!(error.contains("--config -"), "{error}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn server_config_reads_stdin() {
    let (output, _) = run(
        &["--config", "-", "server", "start"],
        b"version: SECRET_MARKER\n",
    );
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("invalid server YAML"), "{error}");
    assert!(!error.contains("SECRET_MARKER"));
}
