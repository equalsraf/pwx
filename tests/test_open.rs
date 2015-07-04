#[macro_use] extern crate matches;

extern crate pwx;
use pwx::{Pwx,Fail};
use std::path::Path;

// FIXME: matches!() is not very informative for this

#[test]
fn test_notfound() {
    let r = Pwx::open(Path::new("no-such-file"), "".as_bytes());
    assert!(matches!(r, Err(Fail::UnableToOpen(_))));
}

#[test]
fn test_open_ok() {
    pwx::Pwx::open(Path::new("tests/test.psafe3"), "test".as_bytes()).unwrap();
}

#[test]
fn test_open_wrongpass() {
    let r = pwx::Pwx::open(Path::new("tests/test.psafe3"), "wrongpass".as_bytes());
    assert!(matches!(r, Err(Fail::WrongPassword)));
}

#[test]
fn test_open_toosmall() {
    let r = pwx::Pwx::open(Path::new("tests/test_toosmall.psafe3"), "test".as_bytes());
    assert!(matches!(r, Err(Fail::ReadError(_))));
}

#[test]
fn test_open_invaltag() {
    let r = pwx::Pwx::open(Path::new("tests/test_invaltag.psafe3"), "test".as_bytes());
    assert!(matches!(r, Err(Fail::InvalidTag)));
}

#[test]
fn test_open_invaliter() {
    let r = pwx::Pwx::open(Path::new("tests/test_invaliter.psafe3"), "test".as_bytes());
    assert!(matches!(r, Err(Fail::InvalidIterationCount)));
}

