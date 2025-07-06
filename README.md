# authware - Its middleware, for auth

This is a collection of basic middlewares that allow you to
authenticate users on a webserver.  It is architected in such a way
that the authenticators are not exclusively locked to HTTP use cases,
and it is possible to get access to the authenticators directly.  You
can also write your own if you want a backend that this library does
not support.

For information on how to use this library, consult the [basic
demo](./demo/basic/).
