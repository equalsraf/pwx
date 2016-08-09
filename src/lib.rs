//!
//! PWS3 database
//!
extern crate crypto;
extern crate secstr;
extern crate byteorder;
extern crate uuid;

use std::fs::File;
use std::path::Path;
use std::io;
use std::io::Seek;
use std::fmt;
use std::collections::HashMap;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{Mac,MacResult};
use std::cmp::min;
use secstr::SecStr;
use byteorder::{LittleEndian, ReadBytesExt};

mod twofish;
use twofish::Key;

pub mod util;
use util::{stretch_pass,read_all};

pub mod pinentry;
pub mod db;
pub use db::{Field, Value};

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
    UnableToInitializeTwofishKey,
    InvalidSalt,
    EOF,
}

impl From<io::Error> for Fail {
    fn from(err: io::Error) -> Self {
        Fail::ReadError(err)
    }
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
            Fail::UnableToInitializeTwofishKey => fmt.write_str("libtwofish failed to initialize a key from the given data"),
            Fail::InvalidSalt => fmt.write_str("Salt is too short"),
            Fail::EOF => fmt.write_str("EOF"),
        }
    }
}

// TODO: mlock
// Keep these in a separate Boxed struct
struct PwxCrypto {
    key_k: Key,
    iv: [u8; BLOCK_SIZE],
    hmac: Hmac<Sha256>,
}

pub struct Pwx {
    crypto: Box<PwxCrypto>,
    /// True if the HMAC has been verified
    auth: bool,
    iter: u32,
    file: File,
    hmac_block_next: u64
    // TODO: path
}

/// Iterate over all dabase records (excluding the db header).
pub struct PwxRecordIterator<'a> {
    inner: PwxFieldIterator<'a>,
}

impl<'a> Iterator for PwxRecordIterator<'a> {
    type Item = Vec<Field>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut rec = Vec::new();

        for (typ,val) in &mut self.inner {
            if typ == 0xff {
                break;
            }

            rec.push(db::Field::from(typ, val));
        }

        if rec.is_empty() {
            None
        } else {
            Some(rec)
        }
    }
}

impl<'a> PwxRecordIterator<'a> {
    pub fn new(db: &'a mut Pwx) -> Result<Self,Fail> {
        let mut inner = try!(PwxFieldIterator::new(db));
        inner.skip_record();
        Ok(PwxRecordIterator {
            inner: inner
        })
    }
}

/// Iterator over all the fields in the database. This might
/// be a bit too low level, see `PwxRecordIterator` for a higher
/// level record iterator.
pub struct PwxFieldIterator<'a> {
    db: &'a mut Pwx,
    cbc_block: SecStr,
    next_block: u64,
}

impl<'a> Iterator for PwxFieldIterator<'a> {
    type Item = (u8,Value);
    fn next(&mut self) -> Option<Self::Item> {
        match self.read_field() {
            Err(_) => None,
            Ok(f) => Some(f),
        }
    }
}

impl<'a> PwxFieldIterator<'a> {
    pub fn new(db: &mut Pwx) -> Result<PwxFieldIterator,Fail> {
        let start = PREAMBLE_SIZE as u64;
        try!(db.file.seek(io::SeekFrom::Start(start)));
        Ok(PwxFieldIterator {
            cbc_block: SecStr::from(&db.crypto.iv[..]),
            db: db,
            next_block: 0,
        })
    }

    /// Decrypt CBC block
    fn decrypt(&mut self, in_data: &[u8], out: &mut [u8]) {
        if in_data.len() < 16 || out.len() < 16 {
            panic!("Received buffer with invalid block size");
        }

        self.db.crypto.key_k.decrypt(in_data, out);

        for i in 0..BLOCK_SIZE {
            out[i] ^= self.cbc_block.unsecure()[i];
            self.cbc_block.unsecure_mut()[i] = in_data[i];
        }
    }

    /// Read and decrypt next block in file
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

    /// Read next field data, HMAC() and return it
    fn read_field(&mut self) -> Result<(u8,Value),Fail> {

        // Read first block
        let mut memory = SecStr::new(vec![0u8; BLOCK_SIZE]);
        let mut plaintext = memory.unsecure_mut();
        match self.read_next_block(plaintext) {
            Some(fail) => return Err(fail),
            None => (),
        }

        let fieldtype = plaintext[4];
        let fieldlen = try!(plaintext.as_ref().read_u32::<LittleEndian>())
                        as usize;
        let mut field_memory = SecStr::new(vec![0u8; fieldlen]);
        let mut pos = 0;

        // Copy first block
        {
            let last = min(11, fieldlen);
            let chunk = &plaintext[5..5+last];
            field_memory.unsecure_mut()[..chunk.len()].clone_from_slice(chunk);
            pos = chunk.len();
            self.db.hmac(self.next_block-1, chunk);
        }

        if fieldlen > 11 {
            // Read rest of the field, one block at a time
            let mut missing = fieldlen-11;
            while missing > 0 {
                match self.read_next_block(plaintext) {
                    Some(fail) => return Err(fail),
                    None => (),
                }

                let count = if missing > BLOCK_SIZE {
                    BLOCK_SIZE
                } else {
                    missing
                };
                let chunk = &plaintext[..count];
                field_memory.unsecure_mut()[pos..pos+chunk.len()].clone_from_slice(chunk);
                self.db.hmac(self.next_block-1, chunk);
                missing -= count;
            }
        }

        Ok((fieldtype, Value::from(field_memory)))
    }

    /// Skip all fields in the current record
    pub fn skip_record(&mut self) {
        for (typ,_) in self {
            if typ == 0xff {
                break;
            }
        }
    }

}

impl Pwx {

    /// Open Database and check the given password
    pub fn open(path: &Path, password: &[u8]) -> Result<Pwx, Fail> {
        let mut file = match File::open(path) {
            Err(why) => return Err(Fail::UnableToOpen(why)),
            Ok(file) => file,
        };

        let mut preamble: [u8; PREAMBLE_SIZE] = [0;PREAMBLE_SIZE];
        try!(read_all(&mut file, &mut preamble));

        let (tag, rest) = preamble.split_at(4);
        if b"PWS3" != tag {
            return Err(Fail::InvalidTag)
        }

        // 32byte SALT
        let (salt, rest) = rest.split_at(SHA256_SIZE);

        // 32bit iteration count(ITER)
        let (iter_bin, rest) = rest.split_at(4);

        let itercount = try!(iter_bin.as_ref().read_u32::<LittleEndian>());
        if itercount < 2048 {
            return Err(Fail::InvalidIterationCount)
        }

        // H(P') - sha256 hash of the stretched pass used to verify
        // the password
        let (h_pline, rest) = rest.split_at(SHA256_SIZE);

        let stretched = match stretch_pass(salt, password, itercount) {
            None => return Err(Fail::InvalidSalt),
            Some(k) => k,
        };
        let mut stretched_hash: [u8; SHA256_SIZE] = [0; SHA256_SIZE];
        let mut sha = Sha256::new();
        sha.input(&stretched);
        sha.result(&mut stretched_hash);

        if stretched_hash != h_pline {
            return Err(Fail::WrongPassword)
        }

        let pline_key = match Key::new(&stretched) {
            None => return Err(Fail::UnableToInitializeTwofishKey),
            Some(k) => k,
        };
        // Decrypt K stored in blocks B1+B2
        let mut k_bin = SecStr::new(vec![0; BLOCK_SIZE*2]);
        let (b1, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b1, k_bin.unsecure_mut());
        let (b2, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b2, &mut k_bin.unsecure_mut()[BLOCK_SIZE..]);
        let key_k = match Key::new(&k_bin.unsecure()) {
            None => return Err(Fail::UnableToInitializeTwofishKey),
            Some(k) => k,
        };
        
        // Decrypt L stored in blocks B3+B4
        let mut l_bin = SecStr::new(vec![0; BLOCK_SIZE*2]);
        let (b3, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b3, l_bin.unsecure_mut());
        let (b4, rest) = rest.split_at(BLOCK_SIZE);
        pline_key.decrypt(b4, &mut l_bin.unsecure_mut()[BLOCK_SIZE..]);

        // IV for CBC
        let (iv, _) = rest.split_at(BLOCK_SIZE);
        let mut arr = [0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            arr[i] = iv[i];
        }

        // TODO: any way to lock this?
        let hmac = Hmac::new(Sha256::new(), l_bin.unsecure());

        debug_assert!(file.seek(io::SeekFrom::Current(0)).unwrap() as usize == PREAMBLE_SIZE);
        let p = Pwx{
            auth: false,
            iter: itercount,
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

    /// Returns true if the file HMAC is valid
    pub fn is_authentic(&mut self) -> bool {
        if self.auth {
            return true;
        }
        {
            let fields = match PwxFieldIterator::new(self) {
                Err(_) => return false,
                Ok(f) => f,
            };

            for _ in fields {
            }
        }
        return self.auth;
    }

    /// Add block to HMAC, unless this block was already added
    fn hmac(&mut self, block: u64, data: &[u8]) {
        if block == self.hmac_block_next {
            self.crypto.hmac.input(data);
            self.hmac_block_next += 1;
        }
    }

    pub fn iter(&mut self) -> Result<PwxRecordIterator, Fail> {
        PwxRecordIterator::new(self)
    }
}

