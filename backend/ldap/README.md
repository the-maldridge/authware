# LDAP

The `ldap` backend connects to a remote LDAP server and and
authenticates the user, then makes a second query for groups.  The
server must support anonymous bind for group searching.

## Configuration Options

This backend will be selected when `ldap` is present in the list of
enabled mechanisms.

Additionally, you must configure the following variables:

    * `AUTHWARE_LDAP_URL`: A URL starting with either `ldap://` or `ldaps://`
    * `AUTHWARE_LDAP_BASEDN`: The root path to search under for users
    * `AUTHWARE_LDAP_GROUPATTR`: The attribute on a user that specifies
      groups.  Unless you know why you're setting this to something
      different, it should usually be set to `memberOf`.
    * `AUTHWARE_LDAP_BIND_TEMPLATE`: The UID template that a user will bind
      as.  Specify as a string with `%s` where the username will go.
