//! PWS3 database
//!
extern crate secstr;
extern crate byteorder;
extern crate uuid;
extern crate chrono;
extern crate twofish as crypto_twofish;
extern crate sha2;
extern crate hmac;

use std::fs::File;
use std::path::Path;
use std::io;
use std::io::{Seek, Read};
use std::fmt;
use sha2::Sha256;
use sha2::Digest;
use hmac::{Hmac, Mac};
use std::cmp::min;
use secstr::SecStr;
use byteorder::{LittleEndian, ReadBytesExt};
use uuid::Uuid;
use chrono::naive::NaiveDateTime;

mod twofish;
use twofish::Key;

pub mod util;
use util::{stretch_pass, from_time_t};

pub mod db;
pub use db::{Field, Value};

const PREAMBLE_SIZE: usize = 152;
const SHA256_SIZE: usize = 32;
const BLOCK_SIZE: usize = 16;

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
            Fail::AuthenticationFailed => {
                fmt.write_str("HMAC validation failed, the file has been tampered!")
            }
            Fail::UnableToInitializeTwofishKey => {
                fmt.write_str("libtwofish failed to initialize a key from the given data")
            }
            Fail::InvalidSalt => fmt.write_str("Salt is too short"),
            Fail::EOF => fmt.write_str("EOF"),
        }
    }
}

/// PWS3 Database metadata, this is stored in the
/// header record.
#[derive(Debug, PartialEq)]
pub struct PwxInfo {
    pub uuid: String,
    /// Last save time
    pub mtime: NaiveDateTime,
    /// Last saved by user
    pub user: String,
    /// Last saved on host
    pub host: String,
    /// Database name
    pub dbname: String,
    /// Database description
    pub description: String,
}

/// Holds Key info and the HMAC retrieved from the
/// DB preamble
pub struct PwxKeyInfo {
    /// The block decryption key K
    key_k: Key,
    /// The HMAC key L
    key_l: SecStr,
    /// The IV for block decryption
    iv: [u8; BLOCK_SIZE],
    /// The iteration count for password stretching
    iter: u32,
}

impl PwxKeyInfo {
    /// Parses the DB preamble, i.e. the first 152 bytes found in a
    /// passwordsafe file.
    ///
    /// The user password is needed to decrypt the preamble fields.
    pub fn parse_preamble(preamble: &[u8; PREAMBLE_SIZE], password: &[u8]) -> Result<PwxKeyInfo, Fail> {
        let (tag, rest) = preamble.split_at(4);
        if b"PWS3" != tag {
            return Err(Fail::InvalidTag);
        }

        // 32byte SALT
        let (salt, rest) = rest.split_at(SHA256_SIZE);

        // 32bit iteration count(ITER)
        let (iter_bin, rest) = rest.split_at(4);

        let itercount = iter_bin.as_ref().read_u32::<LittleEndian>()?;
        if itercount < 2048 {
            return Err(Fail::InvalidIterationCount);
        }

        // H(P') - sha256 hash of the stretched pass used to verify
        // the password
        let (h_pline, rest) = rest.split_at(SHA256_SIZE);

        let stretched = match stretch_pass(salt, password, itercount) {
            None => return Err(Fail::InvalidSalt),
            Some(k) => k,
        };
        let mut sha = Sha256::new();
        sha.update(&stretched);
        let stretched_hash = sha.finalize();

        if stretched_hash.as_slice() != h_pline {
            return Err(Fail::WrongPassword);
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

        Ok(PwxKeyInfo {
            key_k: key_k,
            iter: itercount,
            iv: arr,
            key_l: l_bin,
        })
    }

    /// Start HMAC using the L key
    pub fn hmac(&self) -> Hmac<Sha256> {
        Hmac::new_from_slice(self.key_l.unsecure().as_ref())
            .expect("BUG in hmac init")
    }
}

/// This iterator reads blocks from a source and returns them
/// in cleartext.
///
/// It is assumed the provided reader will read the bytes following
/// the preamble i.e. if this is a file its position must be after
/// the preamble header.
///
/// The iterator stops when it encounters the special EOF block.
pub struct PwxBlockIter<'a, 'b, R: 'b> {
    keys: &'a PwxKeyInfo,
    source: &'b mut R,
    cbc_block: SecStr,
}

impl<'a, 'b, R: Read> PwxBlockIter<'a, 'b, R> {
    pub fn new(keys: &'a PwxKeyInfo, source: &'b mut R) -> PwxBlockIter<'a, 'b, R> {
        PwxBlockIter {
            cbc_block: SecStr::from(&keys.iv[..]),
            source: source,
            keys: keys,
        }
    }

    /// Read and decrypt the next block
    fn read_next_block(&mut self) -> Result<SecStr, Fail> {
        let mut block = [0u8; BLOCK_SIZE];
        self.source.read_exact(&mut block)?;

        if b"PWS3-EOFPWS3-EOF" == &block {
            return Err(Fail::EOF);
        }

        // Decrypt block
        let mut out = SecStr::new(vec![0u8; BLOCK_SIZE]);
        {
            let out_r = out.unsecure_mut();
            self.keys.key_k.decrypt(&block, out_r);
            for i in 0..BLOCK_SIZE {
                out_r[i] ^= self.cbc_block.unsecure()[i];
                self.cbc_block.unsecure_mut()[i] = block[i];
            }
        }
        Ok(out)
    }
}

impl<'a, 'b, R: Read> Iterator for PwxBlockIter<'a, 'b, R> {
    type Item = Result<SecStr, Fail>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.read_next_block() {
            Err(Fail::EOF) => None,
            r => Some(r),
        }
    }
}

/// Iterator over all the database fields. See `PwxRecordIter`
/// for a higher level iterator.
pub struct PwxFieldIter<'a, 'b, R: 'b> {
    blockiter: PwxBlockIter<'a, 'b, R>,
}

impl<'a, 'b, R: Read> PwxFieldIter<'a, 'b, R> {

    /// Creates a new iterator over a Reader
    pub fn new(keys: &'a PwxKeyInfo, r: &'b mut R) -> PwxFieldIter<'a, 'b, R> {
        PwxFieldIter{
            blockiter: PwxBlockIter::new(keys, r),
        }
    }

    fn read_next_field(&mut self) -> Result<(u8, Value), Fail> {
        // Read first block
        let mut firstblock = self.blockiter.read_next_block()?;
        let firstblock_plain = firstblock.unsecure_mut();

        let fieldtype = firstblock_plain[4];
        let fieldlen = firstblock_plain.as_ref().read_u32::<LittleEndian>()? as usize;
        let mut field_memory = SecStr::new(vec![0u8; fieldlen]);

        // Copy first block
        {
            let last = min(BLOCK_SIZE-5, fieldlen);
            let chunk = &firstblock_plain[5..5 + last];
            field_memory.unsecure_mut()[..chunk.len()].clone_from_slice(chunk);
        }

        if fieldlen > BLOCK_SIZE - 5 {
            // Read rest of the field, one block at a time
            for chunk in field_memory.unsecure_mut()[BLOCK_SIZE-5..]
                    .chunks_mut(BLOCK_SIZE) {
                let len = chunk.len();
                let nextblock = self.blockiter.read_next_block()?;
                chunk.clone_from_slice(&nextblock.unsecure()[..len]);
            }
        }
        Ok((fieldtype, Value::from(field_memory)))
    }

    /// Skip all fields in the current record
    pub fn skip_record(&mut self) -> Result<(), Fail> {
        for res in self {
            let (typ, _) = res?;
            if typ == 0xff {
                break;
            }
        }
        Ok(())
    }
}

impl<'a, 'b, R: Read> Iterator for PwxFieldIter<'a, 'b, R> {
    type Item = Result<(u8,Value), Fail>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.read_next_field() {
            Err(Fail::EOF) => None,
            r => Some(r),
        }
    }
}

/// Iterate over database records.
pub struct PwxRecordIter<'a, 'b, R: 'b> {
    fielditer: PwxFieldIter<'a, 'b, R>,
}

impl<'a, 'b, R: Read> PwxRecordIter<'a, 'b, R> {
    pub fn new(keys: &'a PwxKeyInfo, r: &'b mut R) -> Self {
        PwxRecordIter { fielditer: PwxFieldIter::new(keys, r) }
    }

    fn read_next_record(&mut self) -> Result<Vec<Field>, Fail> {
        let mut rec = Vec::new();
        loop {
            match self.fielditer.read_next_field()? {
                // The 0xff field type is the end of a record
                (0xff, _) => break,
                (typ, val) => rec.push(db::Field::from(typ, val)),
            }

        }
        Ok(rec)
    }
}

impl<'a, 'b, R: Read> Iterator for PwxRecordIter<'a, 'b, R> {
    type Item = Result<Vec<Field>, Fail>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.read_next_record() {
            Err(Fail::EOF) => None,
            r => Some(r),
        }
    }
}

pub struct PwxReader {
    keys: PwxKeyInfo,
    file: File,
}

impl PwxReader {
    /// Open Database and check the given password
    pub fn open(path: &Path, password: &[u8]) -> Result<PwxReader, Fail> {
        let mut file = match File::open(path) {
            Err(why) => return Err(Fail::UnableToOpen(why)),
            Ok(file) => file,
        };

        let mut preamble: [u8; PREAMBLE_SIZE] = [0; PREAMBLE_SIZE];
        file.read_exact(&mut preamble)?;
        debug_assert!(file.seek(io::SeekFrom::Current(0)).unwrap() as usize == PREAMBLE_SIZE);

        Ok(PwxReader {
            file: file,
            keys: PwxKeyInfo::parse_preamble(&preamble, password)?,
        })
    }

    /// The password safe DB has an HMAC at the end, generated over
    /// the field data, this method reads all fields and verifies
    /// if it matches.
    pub fn authenticate(&mut self) -> Result<(), Fail> {
        let mut hmac = self.keys.hmac();
        {
            for f in self.fields()? {
                let (_, fielddata) = f?;
                let r = fielddata.as_ref();
                if !r.is_empty() {
                    hmac.update(r);
                }
            }
        }
        let result = hmac.finalize().into_bytes();

        let mut expected = [0u8; SHA256_SIZE];
        self.file.read_exact(&mut expected)?;
        if expected != result.as_slice() {
            return Err(Fail::AuthenticationFailed);
        }
        return Ok(());
    }

    pub fn fields(&mut self) -> Result<PwxFieldIter<File>, Fail> {
        self.file.seek(io::SeekFrom::Start(PREAMBLE_SIZE as u64))?;
        Ok(PwxFieldIter::new(&self.keys, &mut self.file))
    }

    pub fn records(&mut self) -> Result<PwxRecordIter<File>, Fail> {
        self.file.seek(io::SeekFrom::Start(PREAMBLE_SIZE as u64))?;
        let mut fielditer = PwxFieldIter::new(&self.keys, &mut self.file);
        fielditer.skip_record()?;
        Ok(PwxRecordIter { fielditer: fielditer })
    }

    /// Returns database header info
    pub fn info(&mut self) -> Result<PwxInfo, Fail> {
        let mut info = PwxInfo {
            uuid: String::new(),
            mtime: NaiveDateTime::from_timestamp(0, 0),
            user: String::new(),
            host: String::new(),
            dbname: String::new(),
            description: String::new(),
        };

        for f in self.fields()? {
            let (typ, val) = f?;
            match typ {
                0x01 => {
                    info.uuid = Uuid::from_bytes(val.as_ref())
                                    .unwrap_or(Uuid::nil())
                                    .hyphenated()
                                    .to_string()
                }
                0x04 => {
                    info.mtime = from_time_t(val.as_ref())
                                     .unwrap_or(NaiveDateTime::from_timestamp(0, 0))
                }
                0x07 => info.user = String::from_utf8_lossy(val.as_ref()).into_owned(),
                0x08 => info.host = String::from_utf8_lossy(val.as_ref()).into_owned(),
                0x09 => info.dbname = String::from_utf8_lossy(val.as_ref()).into_owned(),
                0x0a => info.description = String::from_utf8_lossy(val.as_ref()).into_owned(),
                0xff => break,
                _ => (),
            }
        }
        Ok(info)
    }
}

