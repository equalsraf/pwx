//
// Tests for the pwx binary
//

use std::process::Command;
use std::env::current_exe;

macro_rules! pwxrun {
    ($($arg:expr),*) => {{
        let mut binpath = current_exe().unwrap()
                        .parent().expect("executable path")
                        .to_path_buf();
        binpath.push("pwx");
        Command::new(&binpath)
            .env("PWX_PASSWORD", "test")
            .env("PWX_DATABASE", "tests/test.psafe3")
            $(.arg($arg))*
            .output().unwrap_or_else(|e| {panic!("Failed to execute pwx({}) {}", binpath.to_string_lossy(), e)})
    }};
}

// Show all entries in the DB
#[test]
fn list() {
    let output = pwxrun!("list");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 3);
}

// Filter by title
#[test]
fn list_title() {
    let output = pwxrun!("list", "-T", "face");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);
}

// Filter by User
#[test]
fn list_user() {
    let output = pwxrun!("list", "-U", "testuser");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);
}

// Filter by Group
#[test]
fn list_group() {
    let output = pwxrun!("list", "-G", "social");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);
    assert!(sout.contains("facebook"));
}

// Filter by URL
#[test]
fn list_url() {
    let output = pwxrun!("list", "-R", "facebook.com");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);
}

// list <filter> searches all text fields
#[test]
fn list_filter() {
    let output = pwxrun!("list", "some");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 2);

    // Filters 
    let output = pwxrun!("list", "-U", "some", "some");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);

    // Narrow a query with multiple filters
    let output = pwxrun!("list", "some", "facebook");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);

    let output = pwxrun!("list", "some", "facebook", "none");
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim().split('\n').count(), 1);
}

#[test]
fn get() {
    // URL
    let output = pwxrun!("get", "43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8", "url");
    assert!(output.status.success());
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim(), "https://facebook.com");

    // Group
    let output = pwxrun!("get", "43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8", "group");
    assert!(output.status.success());
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim(), "social");

    // Group
    let output = pwxrun!("get", "43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8", "notes");
    assert!(output.status.success());
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim(), "Some notes");

    // Command is not set so the command fails
    let output = pwxrun!("get", "43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8", "command");
    assert!(!output.status.success());

    // password
    let output = pwxrun!("get", "63a19136-46d9-4f75-827b-5312574233e8", "password");
    assert!(output.status.success());
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim(), "testpassverylong");

    let output = pwxrun!("get", "43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8", "password");
    let sout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(sout.trim(), "klakdjladklasdfadfla8fd9afaadf8a9f");
}

#[test]
fn getrec() {
    let output = pwxrun!("getrec", "43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8", "{username}\nurl: {url}");
    assert!(output.status.success());
    let sout = String::from_utf8_lossy(&output.stdout);
    println!("{}", sout);
    assert_eq!(sout.trim(), "some@email.com\nurl: https://facebook.com");
}
