
extern crate rpassword;
extern crate byteorder;

use crypto::sha2::Sha256;
use crypto::digest::Digest;
use super::SHA256_SIZE;
use std::ascii::AsciiExt;
use std::io;
use std::io::{Write, stdout};
use super::pinentry::PinEntry;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::naive::datetime::NaiveDateTime;

/// Generate the SHA-256 value of a password after several rounds of
/// stretching. If the salt is too short, this returns None.
///
/// [KEYSTRETCH Section 4.1] http://www.schneier.com/paper-low-entropy.pdf
pub fn stretch_pass(salt: &[u8], pass: &[u8], iter: u32) -> Option<[u8; SHA256_SIZE]> {

    if salt.len() < SHA256_SIZE || iter < 2048 {
        return None;
    }

    let mut sha = Sha256::new();
    sha.input(pass);
    sha.input(salt);
    let mut hash: [u8; SHA256_SIZE] = [0; SHA256_SIZE];
    sha.result(&mut hash);

    for _ in 0..iter {
        sha = Sha256::new();
        sha.input(&hash);
        sha.result(&mut hash);
    }
    Some(hash)
}

/// Matching function for filters - this behaves as
/// a case insensitive substring find. Except it
/// returns false if any of the arguments is empty.
pub fn fuzzy_eq(needle: &str, hay: &str) -> bool {
    if needle.is_empty() || hay.is_empty() {
        return false;
    }

    // FIXME: unicode?
    let h = hay.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    h.find(&n).is_some()
}

/// Read binary data as time_t, i.e. decode 32bit or 64bit sequences
/// as unsigned little endian. [sec. 3.1.3]
pub fn from_time_t(b: &[u8]) -> Option<NaiveDateTime> {
    let mut b_r = b;
    if b.len() == 4 {
        b_r.read_u32::<LittleEndian>()
           .map(|val| NaiveDateTime::from_timestamp(val as i64, 0))
           .ok()
    } else if b.len() == 8 {
        b_r.read_u64::<LittleEndian>()
           .map(|val| NaiveDateTime::from_timestamp(val as i64, 0))
           .ok()
    } else {
        None
    }
}

/// Fill buffer with data from file or fail
pub fn read_all(r: &mut io::Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut count = 0;

    while count < buf.len() {
        let res = r.read(&mut buf[count..]);
        match res {
            Ok(0) => break,
            Ok(done) => count += done,
            Err(err) => return Err(err),
        }
    }

    if count == buf.len() {
        Ok(count)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Unexpected end of file"))
    }
}

/// Get user master password.
///
/// May panic if it can't read a password from the terminal.
pub fn get_password_from_user(description: &str, use_pinentry: bool)
    -> Result<String, String> {

    // Use pinentry to get the user password
    if use_pinentry {
        if let Ok(mut pe) = PinEntry::new() {
            return  pe.set_description(description)
                .set_title("pwx")
                .set_prompt("Password")
                .getpin()
                .map_err(|err| format!("Unable to get password using pinentry: {}", err));
        }
    }

    // Get password from terminal
    println!("{}", description);
    print!("Password: ");
    stdout().flush().unwrap();
    Ok(rpassword::read_password().ok().expect("Unable to read password from console"))
}

#[cfg(test)]
mod tests {
    use super::fuzzy_eq;

    #[test]
    fn test_fuzzy_eq() {
        assert_eq!(fuzzy_eq("", ""), false);
        assert_eq!(fuzzy_eq("needle", ""), false);
        assert_eq!(fuzzy_eq("", "hay"), false);
        assert_eq!(fuzzy_eq("Needle", "needle"), true);
        assert_eq!(fuzzy_eq("needle", "http://nEedle"), true);
    }

}
