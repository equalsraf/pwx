extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;
extern crate rpassword;

use pwx::{Pwx,PwxIterator};
use std::io::{Write,stdout,stderr};
use std::process::exit;
use std::path::Path;
use docopt::Docopt;
use uuid::Uuid;

const USAGE: &'static str = "
Usage: pwx <file> list
       pwx <file> info
       pwx <file> get <uuid> <name>
       pwx <file> set <uuid <name> <val>
       pwx (--help | --version)

Options:
    -h, --help      Show this help message
    -v, --version   Show pwx version
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
    cmd_list: bool,
    cmd_set: bool,
    cmd_get: bool,
    cmd_info: bool,
    flag_version: bool,
}

fn real_main() -> i32 {

    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("pwx {}", VERSION);
        return 0;
    }

    // Get password from terminal
    print!("Password: ");
    stdout().flush().unwrap();
    let password = rpassword::read_password().unwrap();

    let mut p = match Pwx::open(Path::new(&args.arg_file), &password) {
        Err(f) => {
            let _ = writeln!(stderr(), "Error: {}", f);
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

        for (typ,val) in fields {
            match typ {
                0x01 => uuid = Uuid::from_bytes(val.as_ref()).unwrap_or(Uuid::nil()).to_hyphenated_string(),
                0x03 => title = String::from_utf8_lossy(val.as_ref()).into_owned(),
                0x04 => username = String::from_utf8_lossy(val.as_ref()).into_owned(),
                0xff => {
                    println!("{} {}[{}]", uuid, title, username);
                    uuid = String::new();
                    title = String::new();
                    username = String::new();
                }
                _ => (),
            }
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

