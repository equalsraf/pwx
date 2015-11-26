
extern crate rpassword;

use crypto::sha2::Sha256;
use crypto::digest::Digest;
use super::SHA256_SIZE;
use std::ascii::AsciiExt;
use std::io;
use std::path::PathBuf;
use std::env::current_dir;
use std::io::Error as IoError;
use std::io::{Write,stdout};
use super::pinentry::PinEntry;

/// Generate the SHA-256 value of a password after several rounds of stretching.
/// [KEYSTRETCH Section 4.1] http://www.schneier.com/paper-low-entropy.pdf
pub fn stretch_pass(salt: &[u8], pass: &[u8], iter: u32) -> Option<[u8; SHA256_SIZE]> {

    if salt.len() < SHA256_SIZE || iter < 2048{
        return None
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

/// Convert 4 byte slice into u32 (from little endian)
pub fn from_le32(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None
    }
    Some(((b[3] as u32) << 24)
            + ((b[2] as u32) << 16)
            + ((b[1] as u32) << 8)
            + ((b[0] as u32)))
}

/// Convert 8 byte slice into u64 (from little endian)
pub fn from_le64(b: &[u8]) -> Option<u64> {
    if b.len() < 8 {
        return None
    }
    Some(((b[7] as u64) << 56)
            + ((b[6] as u64) << 48)
            + ((b[5] as u64) << 40)
            + ((b[4] as u64) << 32)
            + ((b[3] as u64) << 24)
            + ((b[2] as u64) << 16)
            + ((b[1] as u64) << 8)
            + ((b[0] as u64)))
}

/// Matching function for filters - this behaves as
/// a case insensitive substring find. Except it
/// returns false if any of the arguments is empty.
pub fn fuzzy_eq(needle: &str, hay: &str) -> bool
{
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
pub fn from_time_t(b: &[u8]) -> Option<u64> {
    if b.len() == 4 {
        from_le32(b).map(|val| val as u64)
    } else if b.len() == 8 {
        from_le64(b)
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

/// Convert path to absolute path
pub fn abspath(p: &PathBuf) -> Result<PathBuf,IoError> {
    if p.is_absolute() {
        return Ok(p.to_owned())
    } else {
        match current_dir() {
            Ok(mut cd) => {
                cd.push(p);
                Ok(cd)
            },
            Err(err) => Err(err),
        }
    }
}

/// Get user master password.
///
/// If pinentry is available use it, otherwise fallback
/// to reading user password from the console.
///
/// Returns None if pinentry failed to retrieve a password.
/// May panic if it can't read a password from the terminal.
pub fn get_password_from_user(description: &str, skip_pinentry: bool) -> Option<String> {

    // If available use pinentry to get the user password
    if !skip_pinentry {
        if let Ok(mut pe) = PinEntry::new() {
            match pe.set_description(description)
                .set_title("pwx")
                .set_prompt("Password")
                .getpin() {
                    Ok(pass) => return Some(pass),
                    Err(_) => return None,
                }
        }
    }

    // Get password from terminal
    println!("{}", description);
    print!("Password: ");
    stdout().flush().unwrap();
    Some(rpassword::read_password().ok().expect("Unable to read password from console"))
}

#[cfg(test)]
mod tests {
    use super::from_le32;
    use super::from_le64;
    use super::fuzzy_eq;

    #[test]
    fn test_from_le32() {
        assert_eq!(from_le32(b"\x00\x00\x00\x00").unwrap(), 0);
        assert_eq!(from_le32(b"\x01\x00\x00\x00").unwrap(), 0x01);
        assert_eq!(from_le32(b"\x00\x01\x00\x00").unwrap(), 0x0100);
        assert_eq!(from_le32(b"\x00\x00\x01\x00").unwrap(), 0x010000);
        assert_eq!(from_le32(b"\x00\x00\x00\x01").unwrap(), 0x01000000);
        assert_eq!(from_le32(b"\xff\xff\xff\xff").unwrap(), 0xffffffff);
    
        assert_eq!(from_le32(b""), None);
        assert_eq!(from_le32(b"\xff"), None);
        assert_eq!(from_le32(b"\xff\xff"), None);
        assert_eq!(from_le32(b"\xff\xff\xff"), None);
    }

    #[test]
    fn test_from_le64() {
        assert_eq!(from_le64(b"\x00\x00\x00\x00\x00\x00\x00\x00").unwrap(), 0);
        assert_eq!(from_le64(b"\x01\x00\x00\x00\x00\x00\x00\x00").unwrap(), 0x01);
        assert_eq!(from_le64(b"\x00\x01\x00\x00\x00\x00\x00\x00").unwrap(), 0x0100);
        assert_eq!(from_le64(b"\x00\x00\x01\x00\x00\x00\x00\x00").unwrap(), 0x010000);
        assert_eq!(from_le64(b"\x00\x00\x00\x01\x00\x00\x00\x00").unwrap(), 0x01000000);
        assert_eq!(from_le64(b"\x00\x00\x00\x00\x01\x00\x00\x00").unwrap(), 0x0100000000);
        assert_eq!(from_le64(b"\x00\x00\x00\x00\x00\x01\x00\x00").unwrap(), 0x010000000000);
        assert_eq!(from_le64(b"\x00\x00\x00\x00\x00\x00\x01\x00").unwrap(), 0x01000000000000);
        assert_eq!(from_le64(b"\x00\x00\x00\x00\x00\x00\x00\x01").unwrap(), 0x0100000000000000);
        assert_eq!(from_le64(b"\xff\xff\xff\xff\xff\xff\xff\xff").unwrap(), 0xffffffffffffffff);
    
        assert_eq!(from_le64(b""), None);
        assert_eq!(from_le64(b"\xff"), None);
        assert_eq!(from_le64(b"\xff\xff"), None);
        assert_eq!(from_le64(b"\xff\xff\xff"), None);
        assert_eq!(from_le64(b"\xff\xff\xff\xff"), None);
        assert_eq!(from_le64(b"\xff\xff\xff\xff\xff"), None);
        assert_eq!(from_le64(b"\xff\xff\xff\xff\xff\xff"), None);
    }

    #[test]
    fn test_fuzzy_eq() {
        assert_eq!(fuzzy_eq("", ""), false);
        assert_eq!(fuzzy_eq("needle", ""), false);
        assert_eq!(fuzzy_eq("", "hay"), false);
        assert_eq!(fuzzy_eq("Needle", "needle"), true);
        assert_eq!(fuzzy_eq("needle", "http://nEedle"), true);
    }

}



