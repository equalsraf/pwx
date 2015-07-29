**pwx** is a PasswordSafe compatible password manager.

A minimal implementation of a password manager using the PWS3 format. As it
stands this only supports read operations, you can search for records and get
field values (username, password, etc).

Internally a PWS3 database is a list of records, each record has several fields
(username, password, email, notes, etc). Records are uniquely identified by an
UUID.

List all records for github

    $ pwx list github
    65be679a-bc37-4f10-b986-c55d2cbbea95 github[devy]

Get the password for that account using

    $ pwx get 65be679a-bc37-4f10-b986-c55d2cbbea95 password
    devy.password

Check --help or the docs for additional commands.

## License

The pwx code is licensed under the ISC. The third-party twofish implementation
belongs to Niels Ferguson (check the headers for the licensing terms).

