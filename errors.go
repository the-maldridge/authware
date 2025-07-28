package authware

// ErrDoesNotExist returns when a request is made that does not match
// a configured resource.
type ErrDoesNotExist struct{}

func (e ErrDoesNotExist) Error() string { return "resource does not exist" }

// ErrUnauthenticated returns when a request fails authentication
type ErrUnauthenticated struct{}

func (e ErrUnauthenticated) Error() string { return "authentication failed" }

// ErrBackendInternal is returned whenever a backend has encountered
// an internal error that cannot be surfaced to the user.
type ErrBackendInternal struct{}

func (e ErrBackendInternal) Error() string { return "backend internal error" }
