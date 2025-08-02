package authware

import (
	"context"
	"net/http"
	"time"

	"github.com/meehow/securebytes"
)

// A Factory is an initializer that makes a concrete insantiation of
// an auth method.
type Factory func() (Authenticator, error)

// Authenticator authenticates a user based on some information they
// have provided.  If an authenticator cannot satisfy a given request,
// it should return non-nil and the next authenticator in the chain
// will be tried.  If no authenticator matches, then the request will
// be rejected.
type Authenticator interface {
	AuthUserPassword(context.Context, string, string) error
	UserGroups(context.Context, string) (map[string]struct{}, error)
	Name() string
}

// The UserKey type exists purely as a key to insert into the
// http.Request contxt so that a user can be fished out by
// applications that want to have access to it later.
type UserKey struct{}

// User is the normalized type that is returned for any authenticated
// entity.
type User struct {
	// Identity is whatever was passed as the user identifier.
	// This is a user controlled value, and may not be identical
	// to what was passed into the authentication backend by any
	// of the authenticators.
	Identity string

	// Groups is a map of group names that the user possesses.
	// This will be normalized by a backend as just the name, not
	// any path elements that may be required such as in an LDAP
	// context.
	Groups map[string]struct{}

	// AuthedBy specifies which backend successfully identified
	// this user.
	AuthedBy string
}

// Middleware defines a function that can sit in the handler chain and
// potentially modify the response.
type Middleware func(http.Handler) http.Handler

// BasicMiddleware inserts HTTP basic auth requirements into the
// handler chain.
type BasicMiddleware struct {
	a []Authenticator

	sb *securebytes.SecureBytes

	cookieHandler Middleware
}

// Session contains the information that is encoded into the session
// cookie.
type Session struct {
	Expires time.Time
	User    User
}
