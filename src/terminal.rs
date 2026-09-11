use std::io::{self, Read};
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 4096;

pub(crate) fn read_secret(stdin: bool, prompt: &str) -> io::Result<Zeroizing<String>> {
    read_input(stdin, prompt, false)
}

pub(crate) fn read_totp(stdin: bool, prompt: &str) -> io::Result<Zeroizing<String>> {
    read_input(stdin, prompt, true)
}

fn read_input(stdin: bool, prompt: &str, masked: bool) -> io::Result<Zeroizing<String>> {
    if stdin {
        return read_stdin(io::stdin());
    }
    read_prompt(prompt, masked, "/dev/tty")
}

fn read_prompt(prompt: &str, masked: bool, tty: &str) -> io::Result<Zeroizing<String>> {
    let config = rpassword::ConfigBuilder::new()
        .input_file_path(tty)
        .output_file_path(tty);
    let config = if masked {
        config.password_feedback_mask('*')
    } else {
        config.password_feedback_hide()
    };
    // rpassword raises SIGINT before its terminal guard drops. Defer delivery until cleanup finishes.
    let _interrupt = DeferredInterrupt::new()?;
    rpassword::prompt_password_with_config(prompt, config.build()).map(Zeroizing::new)
}

struct DeferredInterrupt {
    original: libc::sigset_t,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl DeferredInterrupt {
    fn new() -> io::Result<Self> {
        let mut blocked = std::mem::MaybeUninit::uninit();
        let mut original = std::mem::MaybeUninit::uninit();
        let result = unsafe {
            libc::sigemptyset(blocked.as_mut_ptr());
            libc::sigaddset(blocked.as_mut_ptr(), libc::SIGINT);
            libc::pthread_sigmask(libc::SIG_BLOCK, blocked.as_ptr(), original.as_mut_ptr())
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(Self {
            original: unsafe { original.assume_init() },
            _thread: std::marker::PhantomData,
        })
    }
}

impl Drop for DeferredInterrupt {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.original, std::ptr::null_mut());
        }
    }
}

fn read_stdin(reader: impl Read) -> io::Result<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::new());
    reader
        .take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_string(&mut value)?;
    if value.len() > MAX_SECRET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret input exceeds 4096 bytes",
        ));
    }
    let len = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(len);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::ExitStatusExt,
        },
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    fn mode(file: &File) -> libc::termios {
        let mut mode = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), mode.as_mut_ptr()) },
            0
        );
        unsafe { mode.assume_init() }
    }

    fn interrupt_blocked() -> bool {
        let mut mask = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), mask.as_mut_ptr())
            },
            0
        );
        unsafe { libc::sigismember(mask.as_ptr(), libc::SIGINT) == 1 }
    }

    #[test]
    fn prompt_child() {
        let Ok(tty) = std::env::var("SSHCA_TEST_PROMPT_TTY") else {
            return;
        };
        let masked = std::env::var("SSHCA_TEST_PROMPT_MASK").unwrap() == "true";
        let blocked = interrupt_blocked();
        let result = read_prompt("Code: ", masked, &tty);
        assert_eq!(interrupt_blocked(), blocked);
        let expected = std::env::var("SSHCA_TEST_PROMPT_EXPECTED").unwrap();
        if expected == "EOF" {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        } else {
            assert_eq!(&*result.unwrap(), &expected);
        }
    }

    fn exercise(input: &[u8], masked: bool, expected: &str, interrupt: bool) -> Vec<u8> {
        let mut master = -1;
        let mut slave = -1;
        let mut name = [0 as libc::c_char; 256];
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    name.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let tty = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_str()
            .unwrap();
        let original = mode(&slave);
        assert_ne!(original.c_lflag & libc::ISIG, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "terminal::tests::prompt_child", "--nocapture"])
            .env("SSHCA_TEST_PROMPT_TTY", tty)
            .env("SSHCA_TEST_PROMPT_MASK", masked.to_string())
            .env("SSHCA_TEST_PROMPT_EXPECTED", expected)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while mode(&slave).c_lflag & libc::ICANON != 0 {
            if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("prompt did not enter input mode");
            }
            thread::sleep(Duration::from_millis(1));
        }
        master.write_all(input).unwrap();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("prompt did not finish");
            }
            thread::sleep(Duration::from_millis(1));
        };
        if interrupt {
            assert_eq!(status.signal(), Some(libc::SIGINT));
        } else {
            assert!(status.success(), "prompt failed: {status}");
        }
        let restored = mode(&slave);
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_cflag, original.c_cflag);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
        let mut output = Vec::new();
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        while unsafe { libc::poll(&mut poll, 1, 0) } > 0 {
            let mut bytes = [0; 256];
            let count = master.read(&mut bytes).unwrap();
            output.extend_from_slice(&bytes[..count]);
        }
        output
    }

    #[test]
    fn totp_uses_masking_and_both_backspace_keys() {
        assert_eq!(
            exercise(b"\x7f01\x082\x7f23456\r", true, "023456", false),
            b"Code: **\x08 \x08*\x08 \x08*****\r\n"
        );
    }

    #[test]
    fn ctrl_c_restores_terminal_before_process_termination() {
        for masked in [false, true] {
            let output = exercise(b"12\x03", masked, "", true);
            assert_eq!(
                output,
                if masked {
                    b"Code: **\r\n".as_slice()
                } else {
                    b"Code: \r\n"
                }
            );
        }
    }

    #[test]
    fn eof_restores_terminal() {
        for masked in [false, true] {
            assert_eq!(exercise(b"\x04", masked, "EOF", false), b"Code: ");
        }
    }

    #[test]
    fn secrets_stay_hidden_with_unicode_and_editing() {
        assert_eq!(
            exercise(
                "clé🔑\x08\x7fé secret!\n".as_bytes(),
                false,
                "clé secret!",
                false
            ),
            b"Code: \r\n"
        );
        assert_eq!(
            exercise(b"old\x15new wrong \x17key\n", false, "new key", false),
            b"Code: \r\n"
        );
        assert_eq!(exercise(b"\n", false, "", false), b"Code: \r\n");
    }

    #[test]
    fn totp_preserves_input_for_server_validation() {
        assert_eq!(
            exercise(b"a01234567\x1b[D\n", true, "a01234567", false),
            b"Code: *********\r\n"
        );
    }

    #[test]
    fn stdin_preserves_spaces_and_multiline_secrets() {
        assert_eq!(
            &*read_stdin(b" key\ncontents \r\n\n".as_slice()).unwrap(),
            " key\ncontents "
        );
    }

    #[test]
    fn stdin_limits_input_to_4096_bytes() {
        assert_eq!(read_stdin(vec![b'a'; 4096].as_slice()).unwrap().len(), 4096);
        assert_eq!(
            read_stdin(vec![b'a'; 4097].as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn prompt_errors_preserve_the_callers_signal_mask() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-tty");
        let blocked = interrupt_blocked();
        assert!(read_prompt("Code: ", true, missing.to_str().unwrap()).is_err());
        assert_eq!(interrupt_blocked(), blocked);
        {
            let _interrupt = DeferredInterrupt::new().unwrap();
            assert!(read_prompt("Code: ", false, missing.to_str().unwrap()).is_err());
            assert!(interrupt_blocked());
        }
        assert_eq!(interrupt_blocked(), blocked);
    }
}
