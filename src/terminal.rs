use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
};
use zeroize::Zeroizing;

struct Terminal {
    file: File,
    original: libc::termios,
}

impl Terminal {
    fn new(file: File) -> io::Result<Self> {
        let mut original = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(file.as_raw_fd(), original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let terminal = Self {
            file,
            original: unsafe { original.assume_init() },
        };
        let mut mode = terminal.original;
        mode.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
        mode.c_cc[libc::VMIN] = 1;
        mode.c_cc[libc::VTIME] = 0;
        terminal.set_mode(&mode)?;
        Ok(terminal)
    }

    fn set_mode(&self, mode: &libc::termios) -> io::Result<()> {
        loop {
            if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, mode) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn read_totp(&mut self, prompt: &str) -> io::Result<Zeroizing<String>> {
        self.file.write_all(prompt.as_bytes())?;
        self.file.flush()?;
        let mut code = Zeroizing::new(String::with_capacity(6));
        let mut byte = Zeroizing::new([0u8]);
        let mut escape = false;
        let mut sequence = false;
        loop {
            self.file.read_exact(&mut *byte)?;
            if matches!(byte[0], 3 | 4 | b'\r' | b'\n') {
                escape = false;
                sequence = false;
            }
            if escape {
                escape = false;
                sequence = matches!(byte[0], b'[' | b'O');
                continue;
            }
            if sequence {
                sequence = !(0x40..=0x7e).contains(&byte[0]);
                continue;
            }
            match byte[0] {
                27 => escape = true,
                b'\r' | b'\n' => {
                    self.file.write_all(b"\n")?;
                    return Ok(code);
                }
                3 => {
                    self.file.write_all(b"\n")?;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "TOTP input cancelled",
                    ));
                }
                4 if code.is_empty() => {
                    self.file.write_all(b"\n")?;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TOTP input ended",
                    ));
                }
                8 | 127 => {
                    if code.pop().is_some() {
                        self.file.write_all(b"\x08 \x08")?;
                    }
                }
                b'0'..=b'9' if code.len() < 6 => {
                    code.push(char::from(byte[0]));
                    self.file.write_all(b"*")?;
                }
                _ => {}
            }
            self.file.flush()?;
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.set_mode(&self.original);
    }
}

pub(crate) fn read_totp(prompt: &str) -> io::Result<Zeroizing<String>> {
    let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    read_totp_from(file, prompt)
}

fn read_totp_from(file: File, prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut terminal = Terminal::new(file)?;
    let result = terminal.read_totp(prompt);
    terminal.set_mode(&terminal.original)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::FromRawFd, thread};

    fn mode(file: &File) -> libc::termios {
        let mut mode = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), mode.as_mut_ptr()) },
            0
        );
        unsafe { mode.assume_init() }
    }

    fn pty() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    }

    fn exercise(input: &[u8]) -> (io::Result<Zeroizing<String>>, Vec<u8>) {
        let (mut master, slave) = pty();
        let original = mode(&slave);
        assert_ne!(original.c_lflag & libc::ISIG, 0);
        let input_file = slave.try_clone().unwrap();
        let reader = thread::spawn(move || read_totp_from(input_file, "Code: "));
        let mut prompt = [0u8; 6];
        master.read_exact(&mut prompt).unwrap();
        assert_eq!(&prompt, b"Code: ");
        master.write_all(input).unwrap();
        let result = reader.join().unwrap();
        let restored = mode(&slave);
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_cflag, original.c_cflag);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
        let mut output = Vec::new();
        loop {
            let mut byte = [0];
            master.read_exact(&mut byte).unwrap();
            output.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        (result, output)
    }

    #[test]
    fn masks_digits_and_supports_both_backspace_keys() {
        let (result, output) = exercise(b"\x7f01\x082\x7f23456\r");
        assert_eq!(&*result.unwrap(), "023456");
        assert_eq!(output, b"**\x08 \x08*\x08 \x08*****\r\n");
    }

    #[test]
    fn ignores_non_digits_extra_digits_and_escape_sequences() {
        let (result, output) = exercise(b"a01\x1b[3~234567\n");
        assert_eq!(&*result.unwrap(), "012345");
        assert_eq!(output, b"******\r\n");
    }

    #[test]
    fn restores_terminal_after_ctrl_c() {
        let (result, output) = exercise(b"12\x03");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(output, b"**\r\n");
    }

    #[test]
    fn ctrl_c_cancels_incomplete_escape_sequences() {
        for input in [b"\x1b\x03".as_slice(), b"\x1b[3\x03"] {
            let (result, _) = exercise(input);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        }
    }

    #[test]
    fn restores_terminal_after_eof() {
        let (result, _) = exercise(b"\x04");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn restores_terminal_after_io_error() {
        let (_master, slave) = pty();
        let original = mode(&slave);
        let read_only = File::open(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let error = read_totp_from(read_only, "Code: ").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let restored = mode(&slave);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
    }
}
