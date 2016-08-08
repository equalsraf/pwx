extern crate pwx;
use pwx::{Pwx,PwxIterator};
use std::path::Path;

#[test]
fn test_is_authentic () {
    let mut p = Pwx::open(Path::new("tests/test.psafe3"), "test".as_bytes()).unwrap();
    assert_eq!(p.is_authentic(), true);

    let mut p = pwx::Pwx::open(Path::new("tests/test_authfail.psafe3"), "test".as_bytes()).unwrap();
    assert_eq!(p.is_authentic(), false);
}

#[test]
fn test_iterator() {
    let mut p = Pwx::open(Path::new("tests/test.psafe3"), "test".as_bytes()).unwrap();
    assert!(p.is_authentic());

    // If we want to read from the start again, we can get a new
    // Iterator
    {
        let fields = PwxIterator::new(&mut p).unwrap();
        let mut count = 0;
        for _ in fields {
            count += 1;
        }
        assert!(count != 0);
    }
    assert!(p.is_authentic());
}



