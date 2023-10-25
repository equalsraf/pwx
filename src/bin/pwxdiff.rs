
extern crate pwx;
extern crate docopt;
extern crate rpassword;
extern crate gpgagent;
extern crate rust_base58;

use rust_base58::ToBase58;
use pwx::{PwxReader, Field, Value};
use docopt::Docopt;
use std::io::{Write, stderr};
use std::process::exit;
use std::env::current_dir;
use std::path::{PathBuf, Path};

// Get pkg version at compile time
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

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


#[derive(serde::Deserialize, Debug)]
struct Args {
    arg_file1: String,
    arg_file2: String,
    flag_version: bool,
}


fn open_db(path: &Path, description: &str) -> PwxReader {
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
    p
}

fn find_uuid(fields: &[Field]) -> Option<Value> {
    for f in fields {
        if let Field::Uuid(v) = f {
            return Some(v.clone());
        }
    }
    return None;
}

fn main() {
    let args: Args = Docopt::new(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
                                                      "/doc/pwxdiff.docopt")))
                         .and_then(|d| d.deserialize())
                         .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("pwxdiff {}", VERSION);
        exit(0);
    }

    let mut path1 = PathBuf::from(&args.arg_file1);
    path1 = match abspath(&path1) {
        Ok(abs) => abs,
        Err(_) => path1,
    };

    if !path1.exists() {
        let _ = writeln!(stderr(), "File does not exist: {}", path1.to_string_lossy());
        exit(-1);
    }

    let mut path2 = PathBuf::from(&args.arg_file2);
    path2 = match abspath(&path2) {
        Ok(abs) => abs,
        Err(_) => path2,
    };

    if !path2.exists() {
        let _ = writeln!(stderr(), "File does not exist: {}", path2.to_string_lossy());
        exit(-1);
    }

    let description = format!("Opening {}", path1.to_string_lossy());
    let mut p1 = open_db(&path1, &description);

    let description = format!("Opening {}", path2.to_string_lossy());
    let mut p2 = open_db(&path2, &description);

    let p1info = p1.info().unwrap();
    let p2info = p2.info().unwrap();
    if p1info != p2info {
        println!("file1: {:#?}", p1info);
        println!("file2: {:#?}", p2info);
    }
    for rec1 in p1.records().expect("Error reading from <file1>") {
        let rec1 = rec1.unwrap();

        match find_uuid(&rec1) {
            None => {
                let _ = writeln!(stderr(), "Found record with no UUID in file1");
                continue;
            }
            Some(ref uuid1) => {
                let mut found = false;
                for rec2 in p2.records().expect("Error reading from <file2>") {
                    let rec2 = rec2.unwrap();
                    match find_uuid(&rec2) {
                        None => {
                            let _ = writeln!(stderr(), "Found record with no UUID in <file2>");
                            continue;
                        }
                        Some(ref uuid2) if uuid1 == uuid2 => {
                            found = true;
                            if rec2 != rec1 {
                                println!("Records are different {}", uuid1.as_ref().to_base58());
                                for f in rec1 {
                                    println!("- {}", f)
                                }
                                for f in rec2 {
                                    println!("+ {}", f)
                                }
                            }
                            break;
                        }
                        Some(_) => (),
                    }
                }

                if !found {
                    println!("Record not found {}", uuid1.as_ref().to_base58())
                }
            }
        }
    }
}
