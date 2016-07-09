extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;

use pwx::{Pwx,PwxIterator};
use pwx::dbspec;
use std::io::{Write,stderr};
use std::process::exit;
use std::path::PathBuf;
use docopt::Docopt;
use uuid::Uuid;
use pwx::util::{fuzzy_eq, from_time_t, abspath, get_password_from_user};

// Get pkg version at compile time
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_file: String,
    arg_fieldname: String,
    arg_uuid: String,
    arg_filter: Vec<String>,
    flag_url: String,
    flag_group: String,
    flag_username: String,
    flag_title: String,
    flag_quiet: bool,
    cmd_count: bool,
    cmd_list: bool,
    cmd_get: bool,
    cmd_info: bool,
    flag_version: bool,
    flag_pass_interactive: bool,
    flag_no_pinentry: bool,
}

/// Get password
/// 1. If --pass-interactive read from console
/// 2. If PWX_PASSWORD is set use it
/// 3. Otherwise read from console
///
/// This function may panic on encoding issues
fn get_password(args: &Args, description: &str) -> Option<String> {
    let var = std::env::var("PWX_PASSWORD");
    if args.flag_pass_interactive || !var.is_ok() {
        get_password_from_user(description, args.flag_no_pinentry)
    } else {
        Some(var.unwrap())
    }
}

/// Filters for the 'list' command
struct ListFilter<'a> {
    m_url: bool,
    m_group: bool,
    m_username: bool,
    m_title: bool,
    m_filter: Vec<bool>,
    args: &'a Args,
}

impl<'a> ListFilter<'a> {
    fn new(args: &Args) -> ListFilter {
        let mut f = ListFilter {
            m_group: args.flag_group.is_empty(),
            m_url: args.flag_url.is_empty(),
            m_username: args.flag_username.is_empty(),
            m_title: args.flag_title.is_empty(),
            m_filter: Vec::new(),
            args: args,
        };
        for _ in 0..args.arg_filter.len() {
            f.m_filter.push(false);
        }
        f
    }

    fn match_filter(&mut self, val: &str) {
        for i in 0..self.args.arg_filter.len() {
            self.m_filter[i] = self.m_filter[i] || fuzzy_eq(&self.args.arg_filter[i], val);
        }
    }

    /// Process field
    fn process(&mut self, typ: u8, val: &[u8]) {
        match typ {
            0x02 => {
                let s = &String::from_utf8_lossy(val.as_ref());
                self.m_group = self.m_group || fuzzy_eq(&self.args.flag_group, s);
                self.match_filter(s);
            },
            0x03 => {
                let s = &String::from_utf8_lossy(val.as_ref());
                self.m_title = self.m_title || fuzzy_eq(&self.args.flag_title, s);
                self.match_filter(s);
            },
            0x04 => {
                let s = &String::from_utf8_lossy(val.as_ref());
                self.m_username = self.m_username || fuzzy_eq(&self.args.flag_username, s);
                self.match_filter(s);
            },
            0x05 => {
                let s = &String::from_utf8_lossy(val.as_ref());
                self.match_filter(s);
            },
            0x0d => {
                let s = &String::from_utf8_lossy(val.as_ref());
                self.m_url = self.m_url || fuzzy_eq(&self.args.flag_url, s);
                self.match_filter(s);
            },
            0x14 => {
                let s = &String::from_utf8_lossy(val.as_ref());
                self.match_filter(s);
            },
            0xff => *self = ListFilter::new(self.args),
            _ => (),
        }

    }

    /// Returns true if the record matches the filter
    fn matched(&self) -> bool {
        for f in self.m_filter.iter() {
            if *f == false {
                return false;
            }
        }
        self.m_group && self.m_url && self.m_username && self.m_title
    }
}

fn real_main() -> i32 {

    let args: Args = Docopt::new(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/doc/pwx.docopt")))
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

    let mut path = if !args.arg_file.is_empty() {
        PathBuf::from(&args.arg_file)
    } else if !env_db.is_empty() {
        PathBuf::from(&env_db)
    } else {
        std::env::home_dir().expect("Cannot find your HOME path")
            .join(".pwsafe").join("pwsafe.psafe3")
    };

    path = match abspath(&path) {
        Ok(abs) => abs,
        Err(_) => path,
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

    path = match abspath(&path) {
        Ok(abs) => abs,
        Err(_) => path,
    };

    let description = format!("Opening {}", path.to_string_lossy());
    let mut p = match Pwx::open(&path, get_password(&args, &description).expect("Unable to get user password").as_bytes()) {
        Err(f) => {
            let _ = writeln!(stderr(), "Error: {} {}", f, path.to_string_lossy());
            exit(-1);
        },
        Ok(p) => p,
    };

    if !p.is_authentic() {
        return -1;
    }

    if args.cmd_list || args.cmd_count {
        let mut count = 0;
        let mut fields = PwxIterator::from_start(&mut p).unwrap();
        fields.skip_record();

        let mut uuid = String::new();
        let mut title = String::new();
        let mut username = String::new();

        let mut filter = ListFilter::new(&args);
        for (typ,val) in fields {
            match typ {
                0x01 => uuid = Uuid::from_bytes(val.as_ref())
                    .unwrap_or(Uuid::nil())
                    .hyphenated().to_string(),
                0x03 => {
                    title = String::from_utf8_lossy(val.as_ref()).into_owned();
                },
                0x04 => {
                    username = String::from_utf8_lossy(val.as_ref()).into_owned();
                },
                0xff => {
                    if filter.matched() {
                        if args.cmd_count {
                            count += 1
                        } else {
                            println!("{} {}[{}]", uuid, title, username);
                        }
                        uuid = String::new();
                        title = String::new();
                        username = String::new();
                    }
                }
                _ => (),
            }
            filter.process(typ, &val);
        }
        if args.cmd_count {
            println!("{}", count);
        }
    } else if args.cmd_info {

        let fields = PwxIterator::from_start(&mut p).unwrap();
        for (typ,val) in fields {
            match typ {
                0x01 => print!("{} ", Uuid::from_bytes(val.as_ref())
                               .unwrap_or(Uuid::nil())
                               .hyphenated().to_string()),
                0x04 => print!("{} ", from_time_t(val.as_ref())
                                 .expect("Invalid time_t field contents")),
                0x07 => print!("{} ", String::from_utf8_lossy(val.as_ref())),
                0x08 => println!("@{} ", String::from_utf8_lossy(val.as_ref())),
                0x09 => println!("{} ", String::from_utf8_lossy(val.as_ref())),
                0x0a => println!("\"{}\" ", String::from_utf8_lossy(val.as_ref())),
                0xff => break,
                _ => (),
            }
        }
    } else if args.cmd_get {

        let has_ftype = dbspec::field2type(&args.arg_fieldname);
        if has_ftype.is_none() {
            let _ = writeln!(stderr(), "Unknown field: {}", args.arg_fieldname);
            return -1;
        }
        let mtype = has_ftype.unwrap();

        let mut uuid;
        let mut data = String::new();
        let mut found = false;
        let mut fields = PwxIterator::from_start(&mut p).unwrap();
        fields.skip_record();
        for (typ,val) in fields {
            match typ {
                // UUID
                0x01 => {
                    uuid = Uuid::from_bytes(val.as_ref())
                        .unwrap_or(Uuid::nil())
                        .hyphenated().to_string();
                    found = uuid == args.arg_uuid;
                },
                // Save field contents for later
                typ if typ == mtype => {
                    data = if dbspec::is_time_t(typ) {
                        format!("{}", from_time_t(val.as_ref()).expect("Invalid time_t value"))
                    } else {
                        String::from_utf8_lossy(val.as_ref()).into_owned()
                    }
                },
                0xff if found == true  => {
                    if data.is_empty() {
                        let _ = writeln!(stderr(), "Field {} was not found", args.arg_fieldname);
                        return -1;
                    } else {
                        println!("{}", data);
                        return 0;
                    }
                },
                _ => (),
            }
        }

        let _ = writeln!(stderr(), "Unknown record: {}", args.arg_uuid);
        return -1;
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

