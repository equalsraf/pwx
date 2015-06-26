extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;
extern crate rpassword;

use pwx::{Pwx,PwxIterator};
use std::io::{Write,stdout,stderr};
use std::process::exit;
use std::path::PathBuf;
use docopt::Docopt;
use uuid::Uuid;
use pwx::util::fuzzy_eq;

const USAGE: &'static str = "
Usage: pwx [options] [<file>] list [-R URL] [-G GROUP] [-U USERNAME] [-T TITLE] [<filter>]
       pwx [options] [<file>] info
       pwx [options] [<file>] get <uuid> <name>
       pwx [options] [<file>] set <uuid <name> <val>
       pwx (--help | --version)

Options:
    -h, --help          Show this help message
    -v, --version       Show pwx version
    --pass-interactive  Read password from console

Filters:
    -R, --url URL
    -G, --group GROUP
    -U, --username USERNAME
    -T, --title TITLE
";

// Get pkg version at compile time
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

macro_rules! usage {
    ($code:expr, $err:expr) => {{
        let _ = writeln!(std::io::stderr(), "{}\n{}", $err, USAGE);
        return $code;
    }};
}

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_file: String,
    arg_name: String,
    arg_val: String,
    arg_uuid: String,
    arg_filter: String,
    flag_url: String,
    flag_group: String,
    flag_username: String,
    flag_title: String,
    cmd_list: bool,
    cmd_set: bool,
    cmd_get: bool,
    cmd_info: bool,
    flag_version: bool,
    flag_pass_interactive: bool,
}

fn get_password_from_console() -> String {
    // Get password from terminal
    print!("Password: ");
    stdout().flush().unwrap();
    rpassword::read_password().ok().expect("Unable to read password from console")
}

/**
 * Get password
 * 1. If --pass-interactive read from console
 * 2. If PWX_PASSWORD is set use it
 * 3. Otherwise read from console
 *
 * This function may panic on encoding issues
 */
fn get_password(args: &Args) -> String {
    if args.flag_pass_interactive {
        return get_password_from_console();
    }

    let var = std::env::var("PWX_PASSWORD");
    if var.is_ok() {
        return var.unwrap()
    }

    get_password_from_console()
}

/** Filters for the 'list' command */
struct ListFilter<'a> {
    m_url: bool,
    m_group: bool,
    m_username: bool,
    m_title: bool,
    m_filter: bool,
    args: &'a Args,
}

impl<'a> ListFilter<'a> {
    fn new(args: &Args) -> ListFilter {
        ListFilter {
            m_group: args.flag_group.is_empty(),
            m_url: args.flag_url.is_empty(),
            m_username: args.flag_username.is_empty(),
            m_title: args.flag_title.is_empty(),
            m_filter: args.arg_filter.is_empty(),
            args: args,
        }
    }

    /** Process field */
    fn process(&mut self, typ: u8, val: &[u8]) {
        match typ {
            0x02 => {
                self.m_group = self.m_group || fuzzy_eq(&self.args.flag_group, &String::from_utf8_lossy(val.as_ref()));
                self.m_filter = self.m_filter || fuzzy_eq(&self.args.arg_filter, &String::from_utf8_lossy(val.as_ref()));
            },
            0x03 => {
                self.m_title = self.m_title || fuzzy_eq(&self.args.flag_title, &String::from_utf8_lossy(val.as_ref()));
                self.m_filter = self.m_filter || fuzzy_eq(&self.args.arg_filter, &String::from_utf8_lossy(val.as_ref()));
            },
            0x04 => {
                self.m_username = self.m_username || fuzzy_eq(&self.args.flag_username, &String::from_utf8_lossy(val.as_ref()));
                self.m_filter = self.m_filter || fuzzy_eq(&self.args.arg_filter, &String::from_utf8_lossy(val.as_ref()));
            },
            0x05 => {
                self.m_filter = self.m_filter || fuzzy_eq(&self.args.arg_filter, &String::from_utf8_lossy(val.as_ref()));
            },
            0x0d => {
                self.m_url = self.m_url || fuzzy_eq(&self.args.flag_url, &String::from_utf8_lossy(val.as_ref()));
                self.m_filter = self.m_filter || fuzzy_eq(&self.args.arg_filter, &String::from_utf8_lossy(val.as_ref()));
            },
            0x14 => {
                self.m_filter = self.m_filter || fuzzy_eq(&self.args.arg_filter, &String::from_utf8_lossy(val.as_ref()));
            },
            0xff => *self = ListFilter::new(self.args),
            _ => (),
        }

    }

    /** Returns true if the record matches the filter */
    fn matched(&self) -> bool {
        self.m_group && self.m_url && self.m_username && self.m_title && self.m_filter
    }
}

fn real_main() -> i32 {

    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("pwx {}", VERSION);
        return 0;
    }

    // The password safe is one of
    // 1. Command line [<file>]
    // 2. PWX_DATABASE env var
    // 3. ~/.pwsafe/psafe.psafe3
    let env_db = std::env::var("PWX_DATABASE").unwrap_or(String::new());

    let path = if !args.arg_file.is_empty() {
        PathBuf::from(&args.arg_file)
    } else if !env_db.is_empty() {
        PathBuf::from(&env_db)
    } else {
        std::env::home_dir().expect("Cannot find your HOME path")
            .join(".pwsafe").join("pwsafe.psafe3")
    };

    // FIXME: PathBuf::exists is still Unstable, but we need to verify
    // if the file exists before prompting for password
    match std::fs::File::open(&path) {
        Err(err) => {
            let _ = writeln!(stderr(), "{}: {}", path.to_string_lossy(), err);
            return -1;
        },
        _ => (),
    }

    let mut p = match Pwx::open(&path, get_password(&args).as_bytes()) {
        Err(f) => {
            let _ = writeln!(stderr(), "Error: {} {}", f, path.to_string_lossy());
            exit(-1);
        },
        Ok(p) => p,
    };

    if !p.is_authentic() {
        return -1;
    }

    if args.cmd_list {
        let mut fields = PwxIterator::from_start(&mut p).unwrap();
        fields.skip_record();

        let mut uuid = String::new();
        let mut title = String::new();
        let mut username = String::new();

        let mut filter = ListFilter::new(&args);
        for (typ,val) in fields {
            match typ {
                0x01 => uuid = Uuid::from_bytes(val.as_ref()).unwrap_or(Uuid::nil()).to_hyphenated_string(),
                0x03 => {
                    title = String::from_utf8_lossy(val.as_ref()).into_owned();
                },
                0x04 => {
                    username = String::from_utf8_lossy(val.as_ref()).into_owned();
                },
                0xff => {
                    if filter.matched() {
                        println!("{} {}[{}]", uuid, title, username);
                        uuid = String::new();
                        title = String::new();
                        username = String::new();
                    }
                }
                _ => (),
            }
            filter.process(typ, &val);
        }
    } else if args.cmd_info {

        let fields = PwxIterator::from_start(&mut p).unwrap();
        for (typ,val) in fields {
            match typ {
                0x01 => print!("{} ", Uuid::from_bytes(val.as_ref()).unwrap_or(Uuid::nil()).to_hyphenated_string()),
                0x07 => print!("{} ", String::from_utf8_lossy(val.as_ref())),
                0x08 => println!("@{} ", String::from_utf8_lossy(val.as_ref())),
                0x09 => println!("{} ", String::from_utf8_lossy(val.as_ref())),
                0x0a => println!("\"{}\" ", String::from_utf8_lossy(val.as_ref())),
                0xff => break,
                _ => (),
            }
        }
    }

    return 0
}

// Rust set_exit_status cannot be used yet, the only way to
// set an exit code to exit using exit(code) so we wrap the
// main function like this
fn main() {
    let exit_code = real_main();
    exit(exit_code);
}

