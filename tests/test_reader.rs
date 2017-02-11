extern crate pwx;
use pwx::PwxReader;
use std::path::Path;

#[test]
fn test_authenticate() {
    let mut p = PwxReader::open(Path::new("tests/test.psafe3"), b"test").unwrap();
    assert!(p.authenticate().is_ok());
    // A second call will recompute the HMAC from the start, and MUST
    // succeed too.
    assert!(p.authenticate().is_ok());
}

#[test]
fn test_authenticate_fails() {
    let mut p = PwxReader::open(Path::new("tests/test_authfail.psafe3"), b"test").unwrap();
    assert!(p.authenticate().is_err());
    assert!(p.authenticate().is_err());
}

#[test]
fn test_field_iter() {
    let mut p = PwxReader::open(Path::new("tests/test.psafe3"), b"test").unwrap();

    {
        let mut count = 0;
        for field in p.fields().unwrap() {
            field.unwrap();
            count += 1;
        }
        assert_eq!(count, 43);
    }
    // If we want to read from the start again, we can get a new
    // Iterator
    {
        let mut count = 0;
        for field in p.fields().unwrap() {
            field.unwrap();
            count += 1;
        }
        assert_eq!(count, 43);
    }
}

#[test]
fn test_record_iter() {
    let mut p = PwxReader::open(Path::new("tests/test.psafe3"), b"test").unwrap();

    let mut count = 0;
    for rec in p.records().unwrap() {
        rec.unwrap();
        count += 1;
    }
    assert_eq!(count, 3);

    let mut count2 = 0;
    for rec in p.records().unwrap() {
        rec.unwrap();
        count2 += 1;
    }
    assert_eq!(count, count2);
}
