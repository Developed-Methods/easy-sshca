use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
};
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 4096;

#[derive(Clone, Copy)]
enum Input {
    Secret,
    Totp,
}

impl Input {
    fn masked(self) -> bool {
        matches!(self, Self::Totp)
    }

    fn accepts(self, c: char, value: &str) -> bool {
        match self {
            Self::Secret => !c.is_control(),
            Self::Totp => c.is_ascii_digit() && value.len() < 6,
        }
    }
}

pub(crate) fn read_secret(stdin: bool, prompt: &str) -> io::Result<Zeroizing<String>> {
    read_input(stdin, prompt, Input::Secret)
}

pub(crate) fn read_totp(stdin: bool, prompt: &str) -> io::Result<Zeroizing<String>> {
    read_input(stdin, prompt, Input::Totp)
}

fn read_input(stdin: bool, prompt: &str, input: Input) -> io::Result<Zeroizing<String>> {
    if stdin {
        return read_stdin(io::stdin());
    }
    let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    read_from(file, prompt, input)
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

fn read_char(reader: &mut impl Read) -> io::Result<char> {
    let mut bytes = Zeroizing::new([0u8; 4]);
    reader.read_exact(&mut bytes[..1])?;
    let len = match bytes[0] {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UTF-8 input",
            ));
        }
    };
    reader.read_exact(&mut bytes[1..len])?;
    std::str::from_utf8(&bytes[..len])
        .map(|s| s.chars().next().unwrap())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 input"))
}

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

    fn read(&mut self, prompt: &str, input: Input) -> io::Result<Zeroizing<String>> {
        self.file.write_all(prompt.as_bytes())?;
        self.file.flush()?;
        let mut value = Zeroizing::new(String::new());
        let mut escape = false;
        let mut sequence = false;
        loop {
            let c = read_char(&mut self.file)?;
            if matches!(c, '\x03' | '\x04' | '\r' | '\n') {
                escape = false;
                sequence = false;
            }
            if escape {
                escape = false;
                sequence = matches!(c, '[' | 'O');
                continue;
            }
            if sequence {
                sequence = !('\x40'..='\x7e').contains(&c);
                continue;
            }
            match c {
                '\x1b' => escape = true,
                '\r' | '\n' => {
                    return Ok(value);
                }
                '\x03' => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "secret input cancelled",
                    ));
                }
                '\x04' if value.is_empty() => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "secret input ended",
                    ));
                }
                '\x08' | '\x7f' => {
                    if value.pop().is_some() && input.masked() {
                        self.file.write_all(b"\x08 \x08")?;
                    }
                }
                '\x15' | '\x17' => {
                    let keep = if c == '\x15' {
                        0
                    } else {
                        value.trim_end().rfind(' ').map_or(0, |index| index + 1)
                    };
                    while value.len() > keep {
                        value.pop();
                        if input.masked() {
                            self.file.write_all(b"\x08 \x08")?;
                        }
                    }
                }
                c if input.accepts(c, &value) => {
                    if value.len() + c.len_utf8() > MAX_SECRET_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "secret input exceeds 4096 bytes",
                        ));
                    }
                    value.push(c);
                    if input.masked() {
                        self.file.write_all(b"*")?;
                    }
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

fn read_from(file: File, prompt: &str, input: Input) -> io::Result<Zeroizing<String>> {
    let mut terminal = Terminal::new(file)?;
    let result = terminal.read(prompt, input);
    let newline = terminal
        .file
        .write_all(b"\n")
        .and_then(|()| terminal.file.flush());
    terminal.set_mode(&terminal.original)?;
    result.and_then(|value| newline.map(|()| value))
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

    fn exercise(input: &[u8], kind: Input) -> (io::Result<Zeroizing<String>>, Vec<u8>) {
        let (mut master, slave) = pty();
        let original = mode(&slave);
        assert_ne!(original.c_lflag & libc::ISIG, 0);
        let input_file = slave.try_clone().unwrap();
        let reader = thread::spawn(move || read_from(input_file, "Code: ", kind));
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
        let (result, output) = exercise(b"\x7f01\x082\x7f23456\r", Input::Totp);
        assert_eq!(&*result.unwrap(), "023456");
        assert_eq!(output, b"**\x08 \x08*\x08 \x08*****\r\n");
    }

    #[test]
    fn ignores_non_digits_extra_digits_and_escape_sequences() {
        let (result, output) = exercise(b"a01\x1b[3~234567\n", Input::Totp);
        assert_eq!(&*result.unwrap(), "012345");
        assert_eq!(output, b"******\r\n");
    }

    #[test]
    fn restores_terminal_after_ctrl_c() {
        for kind in [Input::Secret, Input::Totp] {
            let (result, output) = exercise(b"12\x03", kind);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert_eq!(
                output,
                if kind.masked() {
                    b"**\r\n".as_slice()
                } else {
                    b"\r\n"
                }
            );
        }
    }

    #[test]
    fn ctrl_c_cancels_incomplete_escape_sequences() {
        for input in [b"\x1b\x03".as_slice(), b"\x1b[3\x03"] {
            let (result, _) = exercise(input, Input::Totp);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        }
    }

    #[test]
    fn restores_terminal_after_eof() {
        for kind in [Input::Secret, Input::Totp] {
            let (result, _) = exercise(b"\x04", kind);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[test]
    fn hides_secrets_and_erases_whole_unicode_characters() {
        let (result, output) = exercise("clé🔑\x08\x7fé secret!\n".as_bytes(), Input::Secret);
        assert_eq!(&*result.unwrap(), "clé secret!");
        assert_eq!(output, b"\r\n");
    }

    #[test]
    fn accepts_empty_secrets_for_public_configuration() {
        let (result, output) = exercise(b"\n", Input::Secret);
        assert!(result.unwrap().is_empty());
        assert_eq!(output, b"\r\n");
    }

    #[test]
    fn supports_clearing_words_and_lines() {
        let (result, output) = exercise(b"old\x15new wrong \x17key\n", Input::Secret);
        assert_eq!(&*result.unwrap(), "new key");
        assert_eq!(output, b"\r\n");
        let (result, output) = exercise(b"12\x1534\x1756\n", Input::Totp);
        assert_eq!(&*result.unwrap(), "56");
        assert_eq!(output, b"**\x08 \x08\x08 \x08**\x08 \x08\x08 \x08**\r\n");
    }

    #[test]
    fn restores_terminal_after_invalid_utf8() {
        let (result, output) = exercise(b"\xff", Input::Secret);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(output, b"\r\n");
    }

    #[test]
    fn stdin_preserves_spaces_and_multiline_secrets() {
        let value = read_stdin(b" key\ncontents \r\n\n".as_slice()).unwrap();
        assert_eq!(&*value, " key\ncontents ");
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
    fn restores_terminal_after_io_error() {
        let (_master, slave) = pty();
        let original = mode(&slave);
        let read_only = File::open(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let error = read_from(read_only, "Code: ", Input::Secret).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let restored = mode(&slave);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_cc, original.c_cc);
    }
}
