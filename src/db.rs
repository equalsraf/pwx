
use std::fmt;
use super::util;
use super::uuid::Uuid;
use super::secstr::SecStr;

#[derive(PartialEq)]
pub enum Field {
    Uuid(Vec<u8>),
    Group(Vec<u8>),
    Title(Vec<u8>),
    Username(Vec<u8>),
    Notes(Vec<u8>),
    Password(Vec<u8>),
    CreationTime(Vec<u8>),
    PasswordModificationTime(Vec<u8>),
    LastAccessTime(Vec<u8>),
    Url(Vec<u8>),
    Command(Vec<u8>),
    Email(Vec<u8>),
    Unknown(u8, Vec<u8>),
}

impl Field {
    pub fn from(typ: u8, val: Vec<u8>) -> Self {
        match typ {
            0x01 => Field::Uuid(val),
            0x02 => Field::Group(val),
            0x03 => Field::Title(val),
            0x04 => Field::Username(val),
            0x05 => Field::Notes(val),
            0x06 => Field::Password(val),
            0x07 => Field::CreationTime(val),
            0x08 => Field::PasswordModificationTime(val),
            0x09 => Field::LastAccessTime(val),
            0x0d => Field::Url(val),
            0x12 => Field::Command(val),
            0x14 => Field::Email(val),
            _ => Field::Unknown(typ, val),
        }
    }

    /// Return human readable field name
    pub fn name(&self) -> Option<&str> {
        match *self {
            Field::Uuid(_) => Some("uuid"),
            Field::Group(_) => Some("group"),
            Field::Title(_) => Some("title"),
            Field::Username(_) => Some("username"),
            Field::Notes(_) => Some("notes"),
            Field::Password(_) => Some("password"),
            Field::CreationTime(_) => Some("ctime"),
            Field::LastAccessTime(_) => Some("atime"),
            Field::Url(_) => Some("url"),
            Field::Email(_) => Some("email"),
            Field::Command(_) => Some("command"),
            _ => None,
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Field::Uuid(ref val) => {
                let uuid = Uuid::from_bytes(val.as_ref())
                    .unwrap_or(Uuid::nil())
                    .hyphenated().to_string();
                fmt.write_str(&uuid)
            }
            Field::Group(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Title(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Username(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Notes(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Password(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::CreationTime(ref val) => {
                let ts = util::from_time_t(&val).unwrap_or(0);
                write!(fmt, "{}", ts)
            }
            Field::PasswordModificationTime(ref val) => {
                let ts = util::from_time_t(&val).unwrap_or(0);
                write!(fmt, "{}", ts)
            }
            Field::LastAccessTime(ref val) => {
                let ts = util::from_time_t(&val).unwrap_or(0);
                write!(fmt, "{}", ts)
            }
            Field::Url(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Email(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Command(ref v)  => {
                let s = String::from_utf8_lossy(v);
                fmt.write_str(&s)
            }
            Field::Unknown(typ, _) => write!(fmt, "Unknown Field({})", typ),
        }
    }
}

