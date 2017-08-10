extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;
extern crate rust_base58;
extern crate chrono;
extern crate rpassword;
extern crate strfmt;
extern crate gpgagent;

use pwx::{PwxReader, Field, Value};
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
    flag_fmt: String,
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

/// Query the database for records that match the given filters
///
/// The function f(recid, recdict) is called for each match. If
/// it returns true, then the query stops.
fn foreach_record<F>(p: &mut PwxReader, args: &Args, mut f: F)
        where F: FnMut(Field, HashMap<String, String>) -> bool {
    let min_pw_age = Duration::days(args.flag_password_age as i64);

    for record in p.records().unwrap() {
        let record = record.expect("Error while reading database");
        let mut recid = None;

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

        let mut recdict = HashMap::new();
        // technically all fields are optional, but we add these two to enable the default
        // format strings to work
        recdict.insert("title".to_owned(), String::new());
        recdict.insert("username".to_owned(), String::new());

        for field in record {
            if let Some(name) = field.name() {
                match field {
                    // The UUID field should respect --long
                    Field::Uuid(ref val) => if args.flag_long {
                        recdict.insert(name.to_owned(), format!("{}", field));
                    } else {
                        recdict.insert(name.to_owned(), val.as_ref().to_base58());
                    },
                    _ => {
                        recdict.insert(name.to_owned(), format!("{}", field));
                    }
                }
            }

            f_keywords.push(&field);
            match field {
                Field::Uuid(_) => {
                    recid = Some(field.clone());
                }
                Field::Title(_) => {
                    let title = format!("{}", field);
                    f_title = f_title || fuzzy_eq(&args.flag_title, &title);
                }
                Field::Username(_) => {
                    let username = format!("{}", field);
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

        if let Some(uuid) = recid {
            if f(uuid, recdict) {
                break;
            }
        }
    }
}

fn cmd_list(p: &mut PwxReader, args: &Args) {
    let fmt = if args.flag_fmt.is_empty() {
        "{uuid} {title} [{username}]\n"
    } else {
        &args.flag_fmt
    };
    foreach_record(p, args, |_, recdict| {
        match fmt.format(&recdict) {
            Ok(s) => {
                print!("{}", s);
            }
            Err(err) => {
                let _ = writeln!(stderr(), "Error applying fmt string: {}", err);
            }
        }
        false
    });
}

fn cmd_get(p: &mut PwxReader, args: &Args) {
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

    foreach_record(p, args, |recid, recdict| {
        if get_uuid == recid {
            if args.cmd_get {
                match recdict.get(&args.arg_fieldname) {
                    Some(f) => {
                        println!("{}", f);
                        exit(0);
                    }
                    None => {
                        let _ = writeln!(stderr(), "Record has no field: {}", args.arg_fieldname);
                        exit(-1);
                    }
                }
            } else {
                match args.arg_fmt.format(&recdict) {
                    Ok(s) => {
                        print!("{}", s);
                        exit(0);
                    }
                    Err(err) => {
                        let _ = writeln!(stderr(), "Error applying fmt string: {}", err);
                        exit(-1);
                    }
                }
            }
            // unreachable
        } else {
            false
        }
    });

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
        match PwxReader::open(&path, var.as_bytes()) {
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

        match PwxReader::open(&path, pass.as_bytes()) {
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

        match PwxReader::open(&path, pass.as_bytes()) {
            Err(err) => {
                let _ = writeln!(stderr(), "Error opening {}: {}", path.to_string_lossy(), err);
                exit(-1);
            }
            Ok(p) => p,
        }
    };

    if !p.authenticate().is_ok() {
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
