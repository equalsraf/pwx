//! Internally a wrapper around rust-crypt twofish.

use crypto_twofish::cipher::crypto_common::KeyInit;
use crypto_twofish::cipher::generic_array::GenericArray;
use crypto_twofish::cipher::{BlockDecrypt, BlockEncrypt};
use crypto_twofish::Twofish;

pub struct Key {
    k: Twofish,
}

impl Key {
    pub fn new(data_in: &[u8]) -> Option<Key> {
        if data_in.len() > 32 {
            return None;
        }

        match Twofish::new_from_slice(data_in) {
            Err(_) => None,
            Ok(k) => Some(Key { k }),
        }
    }

    pub fn decrypt<'a>(&self, data_in: &'a [u8], out: &mut [u8]) {
        if data_in.len() < 16 || out.len() < 16 {
            panic!("Invalid twofish block size");
        }

        let i = GenericArray::from_slice(data_in);
        let o = GenericArray::from_mut_slice(&mut out[..16]);
        self.k.decrypt_block_b2b(i, o)
    }

    #[allow(dead_code)]
    fn encrypt(&self, data_in: &[u8], out: &mut [u8]) {
        let i = GenericArray::from_slice(data_in);
        let o = GenericArray::from_mut_slice(&mut out[..16]);
        self.k.encrypt_block_b2b(i, o)
    }
}

#[cfg(test)]
mod tests {
    use super::Key;

    #[test]
    fn test_256() {
        // Same vector as in twofish.c
        let k = Key::new(&[0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 0xF2, 0xA2, 0x82,
                           0xB7, 0xD4, 0x5B, 0x4E, 0x0D, 0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9,
                           0x2C, 0x1B, 0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F])
                    .unwrap();
        let plaintext = &[0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F, 0x2C, 0x32, 0xDC, 0x23,
                          0x9B, 0x26, 0x35, 0xE6];
        let mut expected_ciphertext = [0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97, 0x05, 0x93,
                                       0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA];

        let mut ciphertext = [0u8; 16];
        k.encrypt(plaintext, &mut ciphertext);
        assert_eq!(&ciphertext, &mut expected_ciphertext);

        let mut plaintext2 = [0u8; 16];
        k.decrypt(&ciphertext, &mut plaintext2);
        assert_eq!(plaintext, &plaintext2);
    }
}

