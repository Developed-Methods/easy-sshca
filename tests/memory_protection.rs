#![cfg(target_os = "linux")]
use easy_sshca::protocol::Operation;

use std::{os::unix::process::CommandExt, process::Command};

#[test]
fn refuses_secrets_when_memory_cannot_be_locked() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_easy-sshca"));
    command.args(["--json", "server", "start", "--config", "/does-not-exist"]);
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["reason"], "MEMORY_PROTECTION_FAILED");
}

#[test]
fn server_init_does_not_require_memory_locking() {
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path().join("instance");
    let mut command = Command::new(env!("CARGO_BIN_EXE_easy-sshca"));
    command
        .args(["server", "init", "--name", "Test CA", "--folder"])
        .arg(&folder);
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(folder.join("server.yaml").is_file());
}

#[test]
fn kernel_protections_cover_existing_and_future_allocations() {
    // Keep process-wide changes outside the parent test runner.
    const CHILD: &str = "EASY_SSHCA_MEMORY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kernel_protections_cover_existing_and_future_allocations",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let existing = vec![42u8; 1024 * 1024];
    easy_sshca::memory::protect().unwrap();
    unsafe {
        assert_eq!(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
        let mut limit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut limit), 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
    fn assert_locked(address: usize) {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut selected = false;
        for line in smaps.lines() {
            if let Some(range) = line.split_whitespace().next()
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                selected = (start..end).contains(&address);
            }
            if selected && line.starts_with("VmFlags:") {
                assert!(line.split_whitespace().any(|flag| flag == "lo"), "{line}");
                return;
            }
        }
        panic!("mapping not found");
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.db");
    let secret = easy_sshca::auth::random_secret();
    let admin = easy_sshca::auth::new_key(easy_sshca::auth::KeyKind::Admin);
    easy_sshca::storage::Database::initialize(&path, &secret, &admin, "memory test").unwrap();
    let mut database = easy_sshca::storage::Database::open(&path, &secret).unwrap();
    database
        .execute(
            Operation::CreateZone,
            &admin,
            &easy_sshca::protocol::Command {
                request_id: easy_sshca::auth::new_id(),
                name: "protected".into(),
                max_duration: 3600,
                ..Default::default()
            },
        )
        .unwrap();
    drop(database);
    let database = easy_sshca::storage::Database::open(&path, &secret).unwrap();
    // Check every writable mapping after SQLCipher has allocated and freed buffers.
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut writable = false;
    let mut mapping_header = "";
    for line in smaps.lines() {
        let mut fields = line.split_whitespace();
        if fields.next().is_some_and(|field| field.contains('-')) {
            mapping_header = line;
            writable = fields
                .next()
                .is_some_and(|permissions| permissions.starts_with("rw"));
        }
        if writable && line.starts_with("VmFlags:") {
            // Linux's vDSO RNG uses droppable pages, which cannot be swapped or locked.
            // Require dump exclusion for these mappings instead.
            if line.split_whitespace().any(|flag| flag == "dp") {
                assert!(line.split_whitespace().any(|flag| flag == "dd"), "{line}");
                continue;
            }
            assert!(
                line.split_whitespace().any(|flag| flag == "lo"),
                "{mapping_header}: {line}"
            );
        }
    }
    drop(database);
    assert_locked(existing.as_ptr() as usize);
    // A new mapping cannot reuse an already locked allocator arena.
    unsafe {
        let mapping = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(mapping, libc::MAP_FAILED);
        mapping.cast::<u8>().write_volatile(42);
        assert_locked(mapping as usize);
        assert_eq!(libc::munmap(mapping, 4096), 0);
    }
    std::thread::spawn(move || {
        let stack_secret = [42u8; 256];
        assert_locked(stack_secret.as_ptr() as usize);
        assert_locked(existing.as_ptr() as usize);
    })
    .join()
    .unwrap();
}

#[test]
fn denied_protection_syscalls_abort_startup() {
    for (syscall, expected) in [
        (libc::SYS_prctl, "cannot disable process dumps"),
        (libc::SYS_prlimit64, "cannot disable core files"),
        (libc::SYS_mlockall, "cannot lock process memory"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_easy-sshca"));
        command.args(["server", "start", "--config", "/does-not-exist"]);
        unsafe {
            command.pre_exec(move || {
                let mut filters = [
                    libc::sock_filter {
                        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                        jt: 0,
                        jf: 0,
                        k: 0,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 1,
                        k: syscall as u32,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_RET | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_RET | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ALLOW,
                    },
                ];
                let program = libc::sock_fprog {
                    len: filters.len() as u16,
                    filter: filters.as_mut_ptr(),
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(expected), "{stderr}");
        assert!(
            !stderr.contains("cannot read server configuration"),
            "{stderr}"
        );
    }
}
