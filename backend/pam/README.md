# PAM

The `pam` backend validates credentials against the local PAM stack.
This backend is not enabled by default, and depends on the PAM headers
being available at compile time.  Usually these are provided by a
package called `pam-devel` or `pam-dev`.

## Configuration Options

By default the backend will authenticate against the `passwd` PAM
stack.  You may change which stack is loaded by setting
`AUTHWARE_PAM_SERVICE` to the name of a valid service configured on
your system.
