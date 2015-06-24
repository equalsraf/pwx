extern crate pwx;
extern crate docopt;
extern crate rustc_serialize;
extern crate uuid;

use pwx::{Pwx,PwxIterator};
use std::io::Write;
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
        exit($code);
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

fn main() {

    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("pwx {}", VERSION);
        return;
    }

    let mut p = match Pwx::open(Path::new(&args.arg_file), "test") {
        Err(f) => usage!(-1, f),
        Ok(p) => p,
    };

    if !p.is_authentic() {
        exit(-1);
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
}

