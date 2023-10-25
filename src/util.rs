
extern crate byteorder;

use sha2::Sha256;
use sha2::Digest;
use super::SHA256_SIZE;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::naive::NaiveDateTime;

/// Generate the SHA-256 value of a password after several rounds of
/// stretching. If the salt is too short, this returns None.
///
/// [KEYSTRETCH Section 4.1] http://www.schneier.com/paper-low-entropy.pdf
pub fn stretch_pass(salt: &[u8], pass: &[u8], iter: u32) -> Option<[u8; SHA256_SIZE]> {

    if salt.len() < SHA256_SIZE || iter < 2048 {
        return None;
    }

    let mut sha = Sha256::new();
    sha.update(pass);
    sha.update(salt);

    let mut hash = sha.finalize();
    for _ in 0..iter {
        let mut sha = Sha256::new();
        sha.update(&hash);
        hash = sha.finalize();
    }
    Some(hash.into())
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
