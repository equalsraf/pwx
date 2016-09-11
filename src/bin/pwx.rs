extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;
extern crate rust_base58;
extern crate chrono;

use pwx::{Pwx, Field, Value};
use std::io::{Write, stderr};
use std::process::exit;
use std::path::PathBuf;
use docopt::Docopt;
use uuid::Uuid;
use rust_base58::{ToBase58, FromBase58};
use pwx::util::{fuzzy_eq, from_time_t, get_password_from_user};
use std::str::from_utf8;
use chrono::Local;
use chrono::duration::Duration;
use std::env::current_dir;

// Get pkg version at compile time
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_file: String,
    arg_fieldname: String,
    arg_recid: String,
    arg_keyword: Vec<String>,
    flag_url: String,
    flag_group: String,
    flag_password_age: u32,
    flag_username: String,
    flag_title: String,
    flag_long: bool,
    flag_quiet: bool,
    cmd_list: bool,
    cmd_get: bool,
    cmd_info: bool,
    flag_version: bool,
    flag_pass_interactive: bool,
    flag_no_pinentry: bool,
}

/// Convert path to absolute path
pub fn abspath(p: &PathBuf) -> Result<PathBuf, std::io::Error> {
    if p.is_absolute() {
        return Ok(p.to_owned());
    } else {
        match current_dir() {
            Ok(mut cd) => {
                cd.push(p);
                Ok(cd)
            }
            Err(err) => Err(err),
        }
    }
}

/// Get password
/// 1. If --pass-interactive read from console
/// 2. If PWX_PASSWORD is set use it
/// 3. Otherwise read from console
///
/// This function may panic on encoding issues
fn get_password(args: &Args, description: &str) -> Result<String, String> {
    let var = std::env::var("PWX_PASSWORD");
    if args.flag_pass_interactive || !var.is_ok() {
        get_password_from_user(description, args.flag_no_pinentry)
    } else {
        Ok(var.unwrap())
    }
}

/// A filter to match multiple keywords
///
/// The default state is for the filter to be unmatched.
/// Push content with 'push()', if it matches the keywords
/// the filter will match.
struct KeywordFilter<'a> {
    m_filter: Vec<bool>,
    args: &'a Args,
}

impl<'a> KeywordFilter<'a> {
    fn new(args: &Args) -> KeywordFilter {
        let mut f = KeywordFilter {
            m_filter: Vec::with_capacity(args.arg_keyword.len()),
            args: args,
        };
        f.m_filter.resize(args.arg_keyword.len(), false);
        f
    }

    /// Attempt to match this filter against a field
    fn push(&mut self, field: &Field) {
        let utf8 = match *field {
            Field::Group(ref v) => from_utf8(v.as_ref()),
            Field::Title(ref v) => from_utf8(v.as_ref()),
            Field::Username(ref v) => from_utf8(v.as_ref()),
            Field::Notes(ref v) => from_utf8(v.as_ref()),
            Field::Password(_) => return,
            Field::Url(ref v) => from_utf8(v.as_ref()),
            _ => return,
        };

        if let Ok(s) = utf8 {
            for (idx, word) in self.args
                                   .arg_keyword
                                   .iter()
                                   .enumerate() {
                self.m_filter[idx] = self.m_filter[idx] || fuzzy_eq(&word, s);
            }
        }
    }

    /// Returns true if all the keywords matched
    fn matched(&self) -> bool {
        self.m_filter.iter().all(|v| *v)
    }
}

fn real_main() -> i32 {

    let args: Args = Docopt::new(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
                                                      "/doc/pwx.docopt")))
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
        std::env::home_dir()
            .expect("Cannot find your HOME path")
            .join(".pwsafe")
            .join("pwsafe.psafe3")
    };

    path = match abspath(&path) {
        Ok(abs) => abs,
        Err(_) => path,
    };

    if !path.exists() {
        let _ = writeln!(stderr(), "File does not exist: {}", path.to_string_lossy());
        return -1;
    }

    path = match abspath(&path) {
        Ok(abs) => abs,
        Err(_) => path,
    };

    let description = format!("Opening {}", path.to_string_lossy());
    let mut p = match Pwx::open(&path,
                                get_password(&args, &description)
                                    .unwrap()
                                    .as_bytes()) {
        Err(f) => {
            let _ = writeln!(stderr(), "Error: {} {}", f, path.to_string_lossy());
            return -1;
        }
        Ok(p) => p,
    };

    if !p.is_authentic() {
        return -1;
    }

    if args.cmd_list {
        let min_pw_age = Duration::days(args.flag_password_age as i64);

        for record in p.iter().unwrap() {
            let mut recid = String::new();
            let mut title = String::new();
            let mut username = String::new();

            // Field filters
            let mut f_username = args.flag_username.is_empty();
            let mut f_title = args.flag_title.is_empty();
            let mut f_url = args.flag_url.is_empty();
            let mut f_group = args.flag_group.is_empty();

            // The password-age filter can use either ctime or ptime
            let mut creation_time = None;
            let mut password_age = None;

            // Keyword filters
            let mut f_keywords = KeywordFilter::new(&args);

            for field in record {
                f_keywords.push(&field);
                match field {
                    Field::Uuid(ref val) =>
                        recid = if args.flag_long {
                            format!("{}", field)
                        } else {
                            val.as_ref().to_base58()
                        },
                    Field::Title(_) => {
                        title = format!("{}", field);
                        f_title = f_title || fuzzy_eq(&args.flag_title, &title);
                    }
                    Field::Username(_) => {
                        username = format!("{}", field);
                        f_username = f_username || fuzzy_eq(&args.flag_username, &username);
                    }
                    Field::Url(_) => {
                        let url = format!("{}", field);
                        f_url = f_url || fuzzy_eq(&args.flag_url, &url);
                    }
                    Field::Group(_) => {
                        let group = format!("{}", field);
                        f_group = f_group || fuzzy_eq(&args.flag_group, &group);
                    }
                    Field::CreationTime(val) => {
                        let ts = from_time_t(val.as_ref()).unwrap();
                        let diff = Local::now().naive_local() - ts;
                        creation_time = Some(diff);
                    }
                    Field::PasswordModificationTime(val) => {
                        let ts = from_time_t(val.as_ref()).unwrap();
                        let diff = Local::now().naive_local() - ts;
                        password_age = Some(diff);
                    }
                    _ => (),
                }
            }

            if !f_username || !f_title || !f_url || !f_group {
                // Skip, record filter did not match
                continue;
            }

            match (creation_time, password_age) {
                // No fields were found treat as a match
                (None, None) => (),
                // Password was never modified
                (Some(diff), None) if diff < min_pw_age => continue,
                // Password modification time
                (_, Some(diff)) if diff < min_pw_age => continue,
                _ => (),
            }

            if !f_keywords.matched() {
                // Skip, generic keyword filter did not match
                continue;
            }

            println!("{} {}[{}]", recid, title, username);
        }
    } else if args.cmd_info {

        let info = p.info().unwrap();
        println!("{} {} {}@{}", info.uuid, info.mtime, info.user, info.host);
    } else if args.cmd_get {
        // Try decoding as base58
        let bin = match args.arg_recid.from_base58() {
            Ok(vec) => vec,
            Err(_) => Uuid::parse_str(&args.arg_recid)
                                .expect("Invalid record id")
                                .as_bytes().to_vec(),
        };
        let get_uuid = Field::Uuid(Value::from(bin));

        for record in p.iter().unwrap() {
            // Find record by UUID
            let mut found = false;
            for field in &record {
                if *field == get_uuid {
                    found = true;
                    break;
                }
            }

            if !found {
                continue;
            }

            // Get field value
            for field in &record {
                if let Some(name) = field.name() {
                    if name == args.arg_fieldname {
                        println!("{}", field);
                        return 0;
                    }
                }
            }
            let _ = writeln!(stderr(), "Unknown field: {}", args.arg_fieldname);
        }

        let _ = writeln!(stderr(), "Unknown record: {}", args.arg_recid);
        return -1;
    }

    return 0;
}

// We want to make sure we exit only after all the destructors
// are called, wait for real_main() to be done before actually
// calling exit.
fn main() {
    let exit_code = real_main();
    exit(exit_code);
}
