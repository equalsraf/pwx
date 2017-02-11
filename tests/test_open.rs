#[macro_use] extern crate matches;

extern crate pwx;
use pwx::{Fail, PwxReader};
use std::path::Path;

// FIXME: matches!() is not very informative for this

#[test]
fn test_notfound() {
    let r = PwxReader::open(Path::new("no-such-file"), b"");
    assert!(matches!(r, Err(Fail::UnableToOpen(_))));
}

#[test]
fn test_open_ok() {
    pwx::PwxReader::open(Path::new("tests/test.psafe3"), b"test").unwrap();
}

#[test]
fn test_open_wrongpass() {
    let r = pwx::PwxReader::open(Path::new("tests/test.psafe3"), b"wrongpass");
    assert!(matches!(r, Err(Fail::WrongPassword)));
}

#[test]
fn test_open_toosmall() {
    let r = pwx::PwxReader::open(Path::new("tests/test_toosmall.psafe3"), b"test");
    assert!(matches!(r, Err(Fail::ReadError(_))));
}

#[test]
fn test_open_invaltag() {
    let r = pwx::PwxReader::open(Path::new("tests/test_invaltag.psafe3"), b"test");
    assert!(matches!(r, Err(Fail::InvalidTag)));
}

#[test]
fn test_open_invaliter() {
    let r = pwx::PwxReader::open(Path::new("tests/test_invaliter.psafe3"), b"test");
    assert!(matches!(r, Err(Fail::InvalidIterationCount)));
}

