package authware

// ErrDoesNotExist returns when a request is made that does not match
// a configured resource.
type ErrDoesNotExist struct {}

func (e ErrDoesNotExist) Error() string { return "resource does not exist" }

