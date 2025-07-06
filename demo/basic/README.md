# Basic Demo

This demo will spin up a trivial web server so that you can see how
the basic auth works.  On startup, try loading http://localhost:8000/
to see the landing page, followed by http://localhost:8000/secure/ to
be challenged for auth.

The demo ships with the following credentials:

  * username: `user`
    password: `password`

By default the demo has the `htpasswd` backend enabled, but you should
be able to enable any backend that is supported for basic auth.

Launch the demo by running:

```
$ go run .
```
