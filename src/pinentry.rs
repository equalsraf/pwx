use std::process::{Command, Child, Stdio, ChildStdin, ChildStdout};
use std::io::Error as IoError;
use std::io::{Write, BufReader, BufRead};
use std::fmt;


// (msg, data)
type CallResult = (String, String);

pub enum PinEntryError {
    IoError(IoError),
    Other(String),
}

impl fmt::Display for PinEntryError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PinEntryError::IoError(ref err) => err.fmt(fmt),
            PinEntryError::Other(ref desc) => write!(fmt, "{}", desc),
        }
    }
}

/// PinEntry client, check the Assuan protocol for
/// details.
pub struct PinEntry {
    cmd: Child,
    pipe_w: ChildStdin,
    pipe_r: BufReader<ChildStdout>,
    timeout: usize,
    description: String,
    prompt: String,
    title: String,
}

impl PinEntry {
    pub fn new() -> Result<PinEntry, PinEntryError> {
        match Command::new("pinentry")
                  .stdin(Stdio::piped())
                  .stdout(Stdio::piped())
                  .stderr(Stdio::null())
                  .spawn() {
            Ok(mut c) => {
                if c.stdin.is_none() || c.stdout.is_none() {
                    Err(PinEntryError::Other("Failed to setup stdin/out".to_owned()))
                } else {
                    let mut p = PinEntry {
                        pipe_w: c.stdin.take().unwrap(),
                        pipe_r: BufReader::new(c.stdout.take().unwrap()),
                        cmd: c,
                        timeout: 0,
                        description: String::new(),
                        prompt: String::new(),
                        title: String::new(),
                    };
                    // Wait for server response
                    match p.wait_response() {
                        Ok(_) => Ok(p),
                        Err(err) => Err(err),
                    }
                }
            }
            Err(err) => Err(PinEntryError::IoError(err)),
        }
    }

    fn call(&mut self, command: &str) -> Result<CallResult, PinEntryError> {
        match self.pipe_w.write_all(command.as_bytes()) {
            Err(err) => return Err(PinEntryError::IoError(err)),
            Ok(_) => (),
        }
        match self.pipe_w.write_all("\n".as_bytes()) {
            Err(err) => return Err(PinEntryError::IoError(err)),
            Ok(_) => (),
        }
        match self.pipe_w.flush() {
            Err(err) => return Err(PinEntryError::IoError(err)),
            Ok(_) => (),
        }

        self.wait_response()
    }

    fn wait_response(&mut self) -> Result<CallResult, PinEntryError> {
        let msg;
        let mut data = String::new();

        loop {
            // Read lines until we get an ERR or an OK
            let mut line = String::new();
            match self.pipe_r.read_line(&mut line) {
                Err(err) => return Err(PinEntryError::IoError(err)),
                Ok(_) => (),
            }

            // With the exception of the trailing NL, the output
            // should have no NL bytes (they are escaped as %0A)
            let resp = line.trim_right_matches("\n");

            if resp.starts_with("OK") {
                msg = resp[2..].to_owned();
                break;
            } else if resp.starts_with("ERR ") {
                msg = resp[3..].to_owned();
                return Err(PinEntryError::Other(msg));
            } else if resp.starts_with("D ") {
                data.push_str(&resp[2..]);
            } else if resp.starts_with("S ") {
            } else if resp.starts_with("INQUIRE") {
                return Err(PinEntryError::Other("Received unsupported INQUIRE from pinentry"
                                                    .to_owned()));
            } else if resp.starts_with("#") {
                // Comments - ignore
            } else {
                // Error
                return Err(PinEntryError::Other("Unsupported response from pinentry".to_owned()));
            }
        }

        // FIXME: unescape data
        Ok((msg, data))
    }

    pub fn set_timeout(&mut self, time: usize) -> &mut Self {
        self.timeout = time;
        self
    }

    pub fn set_description(&mut self, desc: &str) -> &mut Self {
        self.description = desc.to_owned();
        self
    }

    pub fn set_prompt(&mut self, prompt: &str) -> &mut Self {
        self.prompt = prompt.to_owned();
        self
    }

    pub fn set_title(&mut self, title: &str) -> &mut Self {
        self.title = title.to_owned();
        self
    }

    pub fn getpin(&mut self) -> Result<String, PinEntryError> {
        if self.timeout > 0 {
            let cmd = &format!("SETTIMEOUT {}", self.timeout);
            if let Err(err) = self.call(cmd) {
                return Err(err);
            }
        }
        if !self.description.is_empty() {
            let cmd = &format!("SETDESC {}", self.description);
            if let Err(err) = self.call(cmd) {
                return Err(err);
            }
        }
        if !self.prompt.is_empty() {
            let cmd = &format!("SETPROMPT {}", self.prompt);
            if let Err(err) = self.call(cmd) {
                return Err(err);
            }
        }
        if !self.title.is_empty() {
            let cmd = &format!("SETTITLE {}", self.title);
            if let Err(err) = self.call(cmd) {
                return Err(err);
            }
        }
        self.call("GETPIN").map(|ok| ok.1)
    }
}
