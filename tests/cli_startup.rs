use std::process::Command;

#[test]
fn help_and_version_succeed() {
    for args in [vec!["--help"], vec!["--version"], vec!["server", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
}

#[test]
fn client_reaches_configuration_loading() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .args(["--json", "--config"])
        .arg(directory.path().join("missing.yaml"))
        .arg("sign")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["reason"], "INPUT_ERROR");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn core_files_are_disabled() {
    const CHILD: &str = "EASY_SSHCA_CORE_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "core_files_are_disabled"])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    easy_sshca::memory::disable_dumps().unwrap();
    // SAFETY: getrlimit writes to a valid rlimit pointer.
    unsafe {
        let mut limit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut limit), 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn server_still_requires_linux_memory_locking() {
    let output = Command::new(env!("CARGO_BIN_EXE_easy-sshca"))
        .args(["--json", "server", "start", "--config", "/does-not-exist"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["reason"], "MEMORY_PROTECTION_FAILED");
}
