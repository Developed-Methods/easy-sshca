//! Process-wide protections that keep secrets out of core dumps and swap.

use crate::error::{Error, Result};

fn failure(message: impl Into<String>) -> Error {
    Error::failed_precondition("MEMORY_PROTECTION_FAILED", message)
}

/// Disable core files and, on Linux, dumps sent to a pipe collector.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn disable_dumps() -> Result<()> {
    // SAFETY: plain prctl calls with valid constant arguments.
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
    }
    // SAFETY: setrlimit receives a valid rlimit pointer.
    unsafe {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
            return Err(failure(format!(
                "cannot disable core files: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Lock all current and future process memory so secrets are never swapped.
///
/// Call before loading secrets. Do not fork, unlock memory, or change
/// credentials afterward. Repeated calls are no-ops once locking succeeds.
#[cfg(target_os = "linux")]
pub fn protect() -> Result<()> {
    use std::sync::OnceLock;
    static LOCKED: OnceLock<()> = OnceLock::new();

    disable_dumps()?;
    if LOCKED.get().is_some() {
        return Ok(());
    }
    // SAFETY: getrlimit writes into a zeroed rlimit; mlockall takes only flags.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
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
    }
    let _ = LOCKED.set(());
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn disable_dumps() -> Result<()> {
    Err(failure("secret memory protection requires Linux"))
}

#[cfg(not(target_os = "linux"))]
pub fn protect() -> Result<()> {
    Err(failure("secret memory protection requires Linux"))
}
