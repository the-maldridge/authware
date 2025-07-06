# htpasswd

The `htpasswd` backend parses `htpasswd` files as well as `htgroup`
files to provide quick and easy support to add new users and groups.

These files will be loaded from the locations pointed to by
`AUTHWARE_HTPASSWD_FILE` and `AUTHWARE_HTGROUP_FILE` which default to
`.htpasswd` and `.htgroup` respectively.  The file format is as follows:

## `.htpasswd`

The password file is comprised of username and password pairs
seperated by the `:` character.  The password is hashed, with the
following algorithms being supported:

  * SSHA
  * MD5Crypt
  * APR1Crypt
  * SHA
  * Bcrypt
  * Plain text
  * Crypt with SHA-256 and SHA-512

In general its easist to manage this file using the `htpasswd`
utility, which is typically provided by `apache-htpasswd` or
`apache-utils` on most distributions.

## `.htgroup`

The group file must exist even if no groups are defined.  It may be an
empty (zero byte) file.  Groups are defined by a name followed by a
colon, then a space-separated list of members of that group.

Example:

```
group1: user
group2: user
group3:
group4: user admin
```

In this example `user` is a member of `group1`, `group2`, and
`group4`.  The `admin` user is only a member of `group4`.
