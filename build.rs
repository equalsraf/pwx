extern crate gcc;

fn main() {
    gcc::compile_library("libtwofish.a", &["third-party/twofish.c"]);
}

