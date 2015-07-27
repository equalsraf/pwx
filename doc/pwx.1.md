# pwx(1) -- password manager

## SYNOPSIS

`pwx` [options] [&lt;file&gt;] list [-R URL] [-G GROUP] [-U USERNAME] [-T TITLE] [&lt;filter&gt;]<br>
`pwx` [options] [&lt;file&gt;] info<br>
`pwx` [options] [&lt;file&gt;] get &lt;uuid&gt; &lt;fieldname&gt;<br>
`pwx` (--help | --version)<br>


## DESCRIPTION

`pwx` is a CLI password manager, compatible with Password Safe v3. A password safe
database is a list of records, each holding multiple fields with login information
(username, password, url, etc).


### Exit status:

  0    if OK, -1 on error.

## EXAMPLES

The *list* command is used to list entries in the database.

    $ pwx list

List accepts a filter argument, that matches all text fields in a record.

    $ pwx list some
    43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8 facebook[some@email.com]
    63a19136-46d9-4f75-827b-5312574233e8 testthis[testuser]

You can also match specific fields

    $ pwx list --title face
    43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8 facebook[some@email.com]

    $ pwx list --username social
    63a19136-46d9-4f75-827b-5312574233e8 testthis[testuser]

    $ pwx list --group social
    43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8 facebook[some@email.com]

    $ pwx list --url facebook.com
    43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8 facebook[some@email.com]

Or combine multiple filters

    $ pwx list --user some facebook
    43fe1d0e-b65f-4e48-9abf-a1c5a1beeee8 facebook[some@email.com]

All filters MUST match for a record to be printed. Filters are case insensitive.

## FILES

* _~/.pwsafe/pwsafe.psafe3_:
	The user's default password database, if *PWX_DATABASE* is not set and no path is given as argument.

## ENVIRONMENT

* _PWX_PASSWORD_:
	The database password. This can be overriden with `--pass-interactive`.
* _PWX_DATABASE_:
	The database path. This is only used if no `[<file>]` path is given as argument.

