use crate::error::{Error, Result};
use std::sync::OnceLock;

fn failure(message: impl Into<String>) -> Error {
    Error::new(
        tonic::Code::FailedPrecondition,
        "MEMORY_PROTECTION_FAILED",
        message,
    )
}

/// Disable kernel core dumps, including dumps sent to a pipe collector.
pub fn disable_dumps() -> Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(failure(format!(
                "cannot disable process dumps: {}",
                std::io::Error::last_os_error()
            )));
        }
        if libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(failure("process dumpability is not disabled"));
        }
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err(failure(format!(
                "cannot disable core files: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err(failure("secret memory protection requires Linux"))
}

/// Protect Rust heap allocations, stacks, and temporary secret copies.
/// Call before loading secrets. Do not fork, unlock memory, or change credentials afterward.
pub fn protect() -> Result<()> {
    disable_dumps()?;
    static LOCKED: OnceLock<()> = OnceLock::new();
    if LOCKED.get().is_some() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut limit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) != 0 {
            return Err(failure("cannot read the locked-memory limit"));
        }
        // A finite limit can make future heap allocation or stack growth fail.
        if limit.rlim_cur != libc::RLIM_INFINITY {
            return Err(failure(
                "locked-memory limit must be unlimited; configure LimitMEMLOCK=infinity for systemd or ulimit -l unlimited before starting easy-sshca",
            ));
        }
        // ONFAULT avoids populating unused virtual mappings, including thread stacks.
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) != 0 {
            return Err(failure(format!(
                "cannot lock process memory: {}; allow mlockall in the service or container policy",
                std::io::Error::last_os_error()
            )));
        }
        let _ = LOCKED.set(());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err(failure("secret memory protection requires Linux"))
}
