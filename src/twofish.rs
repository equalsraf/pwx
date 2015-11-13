/// Rust wrapper for Niels Ferguson's libtwofish

extern crate libc;
extern crate secstr;
use self::libc::{c_uchar, c_int, c_void};
use self::secstr::SecStr;

const TWOFISH_KEYLEN: usize = 4256;

pub struct Key {
    k: SecStr,
}

extern "C" {
    fn Twofish_initialise();
    fn Twofish_prepare_key(data: *const c_uchar, len: c_int, key: *mut c_void);
    fn Twofish_encrypt(key: *const c_void, data_in: *const c_uchar, data_out: *mut c_uchar);
    fn Twofish_decrypt(key: *const c_void, data_in: *const c_uchar, data_out: *mut c_uchar);
}

impl Key {

    fn nil() -> Key {
        Key { k: SecStr::from(vec![0u8; TWOFISH_KEYLEN]) }
    }

    pub fn new(data_in: &[u8]) -> Option<Key> {
        if data_in.len() > 32 {
            return None
        }

        let mut k = Key::nil();
        unsafe {
            Twofish_initialise();
            Twofish_prepare_key(data_in.as_ptr(), data_in.len() as c_int,
                    k.k.unsecure_mut().as_mut_ptr() as *mut c_void);
        }
        Some(k)
    }

    pub fn decrypt(&self, data_in: &[u8], out: &mut [u8]) {
        if data_in.len() < 16 || out.len() < 16 {
            panic!("Invalid twofish block size");
        }
        unsafe {
            Twofish_decrypt(self.k.unsecure().as_ptr() as *const c_void,
                            data_in.as_ptr(), out.as_mut_ptr());
        }
    }

    pub fn encrypt(&self, data_in: &[u8], out: &mut [u8]) {
        if data_in.len() < 16 || out.len() < 16 {
            panic!("Invalid twofish block size");
        }
        unsafe {
            Twofish_encrypt(self.k.unsecure().as_ptr() as *const c_void,
                            data_in.as_ptr(), out.as_mut_ptr());
        }
    }

}


#[cfg(test)]
mod tests {
    use super::Key;   
    #[test]
    fn test_twofish() {
        let k = Key::nil();

        let plaintext = b"0123456789ABCDEF";
        let mut ciphertext = [0u8; 16];
        k.encrypt(plaintext, &mut ciphertext);
        
        let mut plaintext2 = [0u8; 16];
        k.decrypt(&ciphertext, &mut plaintext2);
        assert_eq!(plaintext, &plaintext2);
    }

    #[test]
    fn test_key_invalid() {
        let k = Key::new(b"0123456789ABCDEF0123456789ABCDEF0");
        assert!(k.is_none());
    }

    // encrypt() and decrypt() panic with slices smaller than 16
    #[test]
    #[should_panic]
    fn test_enc_invalid_in() {Key::nil().encrypt(b"123", &mut [0u8; 16])}
    #[test]
    #[should_panic]
    fn test_enc_invalid_out() {Key::nil().encrypt(&[0u8; 16], &mut [0u8; 3])}
    #[test]
    #[should_panic]
    fn test_dec_invalid_in() {Key::nil().decrypt(b"123", &mut [0u8; 16])}
    #[test]
    #[should_panic]
    fn test_dec_invalid_out() {Key::nil().decrypt(&[0u8; 16], &mut [0u8; 3])}

    #[test]
    fn test_256() {
        // Same vector as in twofish.c
        let k = Key::new(&[
            0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 
            0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
            0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
            0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
            ]).unwrap();
        let plaintext = &[
            0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
            0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
            ];
        let mut expected_ciphertext = [
            0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
            0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
            ];

        let mut ciphertext = [0u8; 16];
        k.encrypt(plaintext, &mut ciphertext);
        assert_eq!(&ciphertext, &mut expected_ciphertext);
        
        let mut plaintext2 = [0u8; 16];
        k.decrypt(&ciphertext, &mut plaintext2);
        assert_eq!(plaintext, &plaintext2);
    }
}
