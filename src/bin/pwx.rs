extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;
extern crate rust_base58;
extern crate chrono;
extern crate rpassword;
extern crate strfmt;
extern crate gpgagent;

use pwx::{Pwx, Field, Value};
use std::io::{Write, stderr};
use std::process::exit;
use std::path::PathBuf;
use std::collections::HashMap;
use docopt::Docopt;
use uuid::Uuid;
use rust_base58::{ToBase58, FromBase58};
use pwx::util::{fuzzy_eq, from_time_t};
use std::str::from_utf8;
use chrono::Local;
use chrono::duration::Duration;
use std::env::current_dir;
use strfmt::Format;

// Get pkg version at compile time
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_file: String,
    arg_fieldname: String,
    arg_recid: String,
    arg_keyword: Vec<String>,
    arg_fmt: String,
    flag_url: String,
    flag_group: String,
    flag_password_age: u32,
    flag_username: String,
    flag_title: String,
    flag_long: bool,
    flag_quiet: bool,
    cmd_list: bool,
    cmd_get: bool,
    cmd_getrec: bool,
    cmd_info: bool,
    flag_version: bool,
}

/// Convert path to absolute path
pub fn abspath(p: &PathBuf) -> Result<PathBuf, std::io::Error> {
    if p.is_absolute() {
        Ok(p.to_owned())
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
            Field::Group(ref v) |
            Field::Title(ref v) |
            Field::Username(ref v) |
            Field::Notes(ref v) |
            Field::Url(ref v) => from_utf8(v.as_ref()),
            Field::Password(_) => return,
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

fn cmd_list(p: &mut Pwx, args: &Args) {
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
                Field::Uuid(ref val) => {
                    recid = if args.flag_long {
                        format!("{}", field)
                    } else {
                        val.as_ref().to_base58()
                    }
                }
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
}

fn cmd_get(p: &mut Pwx, args: &Args) {
    // Try decoding as base58
    let bin = match args.arg_recid.from_base58() {
        Ok(vec) => vec,
        Err(_) => {
            Uuid::parse_str(&args.arg_recid)
                .expect("Invalid record id")
                .as_bytes()
                .to_vec()
        }
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

        let mut recdict = HashMap::new();
        // Get field value
        for field in &record {
            if let Some(name) = field.name() {
                if args.cmd_get && args.arg_fieldname == name {
                    println!("{}", field);
                    exit(0);
                } else if args.cmd_getrec {
                    recdict.insert(name.to_owned(), format!("{}", field));
                }
            }
        }

        if args.cmd_get {
            let _ = writeln!(stderr(), "Unknown field: {}", args.arg_fieldname);
        } else {
            // getrec
            print!("{}",
                   args.arg_fmt.format(&recdict).expect("Error applying format string"));
            exit(0);
        }
    }

    let _ = writeln!(stderr(), "Unknown record: {}", args.arg_recid);
    exit(-1);
}

fn main() {
    let args: Args = Docopt::new(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
                                                      "/doc/pwx.docopt")))
                         .and_then(|d| d.decode())
                         .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("pwx {}", VERSION);
        exit(0);
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
        exit(-1);
    }

    path = match abspath(&path) {
        Ok(abs) => abs,
        Err(_) => path,
    };

    let description = format!("Opening {}", path.to_string_lossy());


    let mut p = if let Ok(var) = std::env::var("PWX_PASSWORD") {
        match Pwx::open(&path, var.as_bytes()) {
            Err(err) => {
                let _ = writeln!(stderr(), "Error opening {} with $PWX_PASSWORD: {}", path.to_string_lossy(), err);
                exit(-1);
            }
            Ok(p) => p,
        }
    } else if let Ok(mut agent) = gpgagent::GpgAgent::from_standard_paths() {
        let _ = agent.setopt_ttyname();
        let cache_id = format!("pwx:{}", path.to_string_lossy());
        let pass = agent.get_passphrase(&cache_id, "pwx", "Password", &description)
            .map(|p| String::from_utf8(p).unwrap())
            .expect("Unable to get password using gpg-agent");

        match Pwx::open(&path, pass.as_bytes()) {
            Err(err) => {
                let _ = writeln!(stderr(), "Error opening {} using gpg-agent: {}", path.to_string_lossy(), err);
                let _ = agent.clear_passphrase(&cache_id);
                exit(-1);
            }
            Ok(p) => p,
        }
    } else {
        // Get password from terminal
        if !args.flag_quiet {
            let _ = write!(stderr(), "{}\n", description);
        }
        let pass = rpassword::prompt_password_stderr("Password: ")
            .expect("Unable to read password from console");

        match Pwx::open(&path, pass.as_bytes()) {
            Err(err) => {
                let _ = writeln!(stderr(), "Error opening {}: {}", path.to_string_lossy(), err);
                exit(-1);
            }
            Ok(p) => p,
        }
    };

    if !p.is_authentic() {
        exit(-1);
    }

    if args.cmd_list {
        cmd_list(&mut p, &args)
    } else if args.cmd_info {

        let info = p.info().unwrap();
        println!("{} {} {}@{}", info.uuid, info.mtime, info.user, info.host);
    } else if args.cmd_get || args.cmd_getrec {
        cmd_get(&mut p, &args)
    }
}
