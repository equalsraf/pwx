extern crate gcc;

use std::fs::File;
use std::io::Write;

/// Convert docopt segment to markdown
///
/// - replace pwx with `pwx` for formatting
/// - append <br> tag at EOL
/// - remove whitespace from line start
/// - replace <> with entities &lt; &gt;
fn ronn_synopsis() -> String {
    let d = String::from(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/doc/pwx.docopt"))
);
    let mut out = String::new();
    for line in d.trim().trim_left_matches(|c:char| !c.is_whitespace()).trim().lines() {
        if line.is_empty() {
            break;
        }
        out.push_str(line.replace("pwx", "`pwx`")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .trim());
        out.push_str("<br>\n");
    }
    out
}

/// Read /doc/pwx.1.md.in and write /doc/pwx.1.md
fn build_markdown() {
    let s = format!(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/doc/pwx.1.md.in")), synopsis=ronn_synopsis());
    let mut f = File::create(concat!(env!("CARGO_MANIFEST_DIR"), "/doc/pwx.1.md")).unwrap();
    f.write_all(s.as_ref()).unwrap();
}

fn main() {
    // Build twofish
    gcc::compile_library("libtwofish.a", &["third-party/twofish.c"]);

    // Generate markdown docs
    build_markdown();

}

