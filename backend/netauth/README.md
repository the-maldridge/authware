# NetAuth

The `netauth` backend makes calls to a remote
[NetAuth](https://netauth.org/) service which will attempt basic
authentication using entity secrets.  This backend is fully configured
by the system NetAuth config file, usually found in
`/etc/netauth/config.toml`, however the file will also be searched for
in the user's home directory, and in the current directory.
