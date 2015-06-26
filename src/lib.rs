/**
 * PWS3 database
 */
extern crate crypto;

use std::fs::File;
use std::path::Path;
use std::error::Error;
use std::io;
use std::io::Seek;
use std::fmt;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{Mac,MacResult};
use std::cmp::min;

mod twofish;
use twofish::Key;

pub mod util;
use util::{from_le32,stretch_pass};

const PREAMBLE_SIZE:usize = 152;
const SHA256_SIZE:usize = 32;
const BLOCK_SIZE:usize = 16;

#[derive(Debug)]
pub enum Fail {
    UnableToOpen(io::Error),
    ReadError(io::Error),
    InvalidTag,
    InvalidIterationCount,
    WrongPassword,
    AuthenticationFailed,
    EOF,
}

impl fmt::Display for Fail {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Fail::UnableToOpen(ref s) => s.fmt(fmt),
            Fail::ReadError(ref s) => s.fmt(fmt),
            Fail::InvalidTag => fmt.write_str("Invalid DB Tag"),
            Fail::InvalidIterationCount => fmt.write_str("Invalid DB, iteration count is too low"),
            Fail::WrongPassword => fmt.write_str("Wrong Password for DB"),
            Fail::AuthenticationFailed => fmt.write_str("HMAC validation failed, the file has been tampered!"),
            Fail::EOF => fmt.write_str("EOF"),
        }
    }
}

// TODO: mlock
/**
 * Keep these in a separate Boxed struct
 */
struct PwxCrypto {
    key_k: Key,
    iv: [u8; BLOCK_SIZE],
    hmac: Hmac<Sha256>,
}

pub struct Pwx {
    crypto: Box<PwxCrypto>,
    /**True if the HMAC has been verified*/
    auth: bool,
    iter: u32,
    file: File,
    hmac_block_next: u64
    // TODO: path
}

pub struct PwxIterator<'a> {
    db: &'a mut Pwx,
    cbc_block: [u8; BLOCK_SIZE],
    next_block: u64,
}

impl<'a> Iterator for PwxIterator<'a> {
    type Item = (u8,Vec<u8>);
    fn next(&mut self) -> Option<Self::Item> {
        match self.read_field() {
            Err(_) => None,
            Ok(f) => Some(f),
        }
    }
}

impl<'a> PwxIterator<'a> {

    pub fn from_start(db: &mut Pwx) -> Result<PwxIterator,Fail> {
        let mut r = match PwxIterator::new(db) {
            Err(err) => return Err(err),
            Ok(r) => r,
        };

        match r.db.file.seek(io::SeekFrom::Start(PREAMBLE_SIZE as u64)) {
            Err(err) => return Err(Fail::ReadError(err)),
            Ok(_) => (),
        }
        r.next_block = 0;
        Ok(r)
    }

    pub fn new(db: &mut Pwx) -> Result<PwxIterator,Fail> {
        let start = PREAMBLE_SIZE as u64;
        match db.file.seek(io::SeekFrom::Current(0)) {
            Err(err) => return Err(Fail::ReadError(err)),
            Ok(pos) if pos < start => panic!("BUG invalid file position, before end of preamble."),
            Ok(pos) if (pos-start) % 16 != 0 => panic!("BUG invalid file position, not a multiple of block size"),
            Ok(pos) => Ok(PwxIterator {
                cbc_block: db.crypto.iv,
                db: db,
                next_block: ((pos as u64)-start)/16,
            }),
        }
    }

    /** CBC decrypt block */
    fn decrypt(&mut self, in_data: &[u8], out: &mut [u8]) {
        if in_data.len() < 16 || out.len() < 16 {
            panic!("Received buffer with invalid block size");
        }

        self.db.crypto.key_k.decrypt(in_data, out);

        for i in 0..BLOCK_SIZE {
            out[i] ^= self.cbc_block[i];
            self.cbc_block[i] = in_data[i];
        }
    }

    /** Read and decrypt next block in file */
    fn read_next_block(&mut self, out: &mut [u8]) -> Option<Fail> {
        let mut block = [0u8; BLOCK_SIZE];
        match read_all(&mut self.db.file, &mut block) {
            Ok(_) => (),
            Err(err) => return Some(Fail::ReadError(err)),
        }
        self.next_block += 1;

        if b"PWS3-EOFPWS3-EOF" == &block {
            let mut expected = [0u8; SHA256_SIZE];
            match read_all(&mut self.db.file, &mut expected) {
                Ok(_) => (),
                Err(err) => return Some(Fail::ReadError(err)),
            }
            
            let expected_mac = MacResult::new(&expected);
            if expected_mac != self.db.crypto.hmac.result() {
                return Some(Fail::AuthenticationFailed);
            }
            self.db.auth = true;
            return Some(Fail::EOF);
        }

        self.decrypt(&block, out);
        None
    }

    /**
     * Read next field data, HMAC() and return it
     */
    fn read_field(&mut self) -> Result<(u8,Vec<u8>),Fail> {

        // Read first block
        let mut plaintext = [0u8; BLOCK_SIZE];
        match self.read_next_block(&mut plaintext) {
            Some(fail) => return Err(fail),
            None => (),
        }

        let fieldtype = plaintext[4];
        let fieldlen = from_le32(&plaintext).unwrap() as usize;
        let mut data: Vec<u8> = Vec::new();
        data.reserve(fieldlen);

        // Copy first block
        {
            let last = min(11, fieldlen);
            let chunk = &plaintext[5..5+last];
            for byte in chunk {
                data.push(byte.clone());
            }
            self.db.hmac(self.next_block-1, chunk);
        }

        if fieldlen > 11 {
            // Read rest of the field, one block at a time
            let mut missing = fieldlen-11;
            while missing > 0 {
                match self.read_next_block(&mut plaintext) {
                    Some(fail) => return Err(fail),
                    None => (),
                }

                let count = if missing > BLOCK_SIZE {
                    BLOCK_SIZE
                } else {
                    missing
                };
                let chunk = &plaintext[..count];
                for byte in chunk {
                    data.push(byte.clone());
                }
                self.db.hmac(self.next_block-1, chunk);
                missing -= count;
            }
        }

        Ok((fieldtype,data))
    }

    /**Skip all fields in the current record*/
    pub fn skip_record(&mut self) {
        for (typ,_) in self {
            if typ == 0xff {
                break;
            }
        }
    }

}

impl Pwx {
    /**
     * Open Database and check the given password
     */
    pub fn open(path: &Path, password: &[u8]) -> Result<Pwx, Fail> {
        let mut file = match File::open(path) {
            Err(why) => return Err(Fail::UnableToOpen(why)),
            Ok(file) => file,
        };

        let mut preamble: [u8; PREAMBLE_SIZE] = [0;PREAMBLE_SIZE];
        match read_all(&mut file, &mut preamble) {
            Err(err) => return Err(Fail::ReadError(err)),
            _ => (),
        }

        let (tag, rest) = preamble.split_at(4);
        if b"PWS3" != tag {
            return Err(Fail::InvalidTag)
        }

        // 32byte SALT
        let (salt, rest) = rest.split_at(SHA256_SIZE);

        // 32bit iteration count(ITER)
        let (iter_bin, rest) = rest.split_at(4);
        let iter = from_le32(iter_bin).unwrap();
        if iter < 2048 {
            return Err(Fail::InvalidIterationCount)
        }

        // H(P') - sha256 hash of the stretched pass used to verify
        // the password
        let (h_pline, rest) = rest.split_at(SHA256_SIZE);

        let stretched = stretch_pass(salt, password, iter).unwrap();
        let mut stretched_hash: [u8; SHA256_SIZE] = [0; SHA256_SIZE];
        let mut sha = Sha256::new();
        sha.input(&stretched);
        sha.result(&mut stretched_hash);

        if stretched_hash != h_pline {
            return Err(Fail::WrongPassword)
        }

        let pline_key = Key::new(&stretched).unwrap();
        // Decrypt K stored in blocks B1+B2
        let mut k_bin: [u8; BLOCK_SIZE*2] = [0; BLOCK_SIZE*2];
        let (b1, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b1, &mut k_bin);
        let (b2, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b2, &mut k_bin[BLOCK_SIZE..]);
        let key_k = Key::new(&k_bin).unwrap();
        
        // Decrypt L stored in blocks B3+B4
        let mut l_bin: [u8; BLOCK_SIZE*2] = [0; BLOCK_SIZE*2];
        let (b3, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b3, &mut l_bin);
        let (b4, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b4, &mut l_bin[BLOCK_SIZE..]);

        // IV for CBC
        let (iv, _) = rest.split_at(BLOCK_SIZE);
        let mut arr = [0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            arr[i] = iv[i];
        }

        let hmac = Hmac::new(Sha256::new(), &l_bin);

        assert!(file.seek(io::SeekFrom::Current(0)).unwrap() as usize == PREAMBLE_SIZE);
        let p = Pwx{
            auth: false,
            iter: 2048,
            file: file,
            hmac_block_next: 0,
            crypto: Box::new(PwxCrypto {
                key_k: key_k,
                iv: arr,
                hmac: hmac,
            })
        };

        Ok(p)
    }

    /**Returns true if the file HMAC is valid*/
    pub fn is_authentic(&mut self) -> bool {
        if self.auth {
            return true;
        }
        {
            let fields = match PwxIterator::new(self) {
                Err(_) => return false,
                Ok(f) => f,
            };

            for _ in fields {
            }
        }
        return self.auth;
    }

    /**
     * Add block to HMAC, unless this block was already added
     */
    fn hmac(&mut self, block: u64, data: &[u8]) {
        if block == self.hmac_block_next {
            self.crypto.hmac.input(data);
            self.hmac_block_next += 1;
        }
    }
}

/**
 * Fill buffer with data from file or fail
 */
fn read_all(r: &mut io::Read, buf: &mut [u8]) -> io::Result<usize> {
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

