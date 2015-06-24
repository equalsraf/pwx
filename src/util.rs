
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use super::SHA256_SIZE;

/**
 * Generate the SHA-256 value of a password after several rounds of stretching.
 * [KEYSTRETCH Section 4.1] http://www.schneier.com/paper-low-entropy.pdf
 */
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

/**Convert 4 byte slice into u32 (from little endian)*/
pub fn from_le32(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None
    }
    Some(((b[3] as u32) << 24)
            + ((b[2] as u32) << 16)
            + ((b[1] as u32) << 8)
            + ((b[0] as u32)))
}

#[cfg(test)]
mod tests {
    use super::from_le32;

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
    
}

