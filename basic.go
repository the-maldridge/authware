package authware

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/meehow/securebytes"
)

// NewAuth returns a basic auth middleware.
func NewAuth() (*BasicMiddleware, error) {
	x := new(BasicMiddleware)

	ai, ok := os.LookupEnv("AUTHWARE_BASIC_MECHS")
	authsList := strings.Split(ai, ":")
	if len(authsList) == 0 || !ok {
		authsList = []string{"htpasswd"}
		slog.Warn("No auth mechanisms specified, defaulting to built in list", "list", authsList)
	}
	for _, mech := range authsList {
		a, err := Initialize(mech)
		if err != nil {
			slog.Error("Could not initialize auth", "mechanism", mech, "error", err)
			return nil, err
		}
		x.a = append(x.a, a)
	}

	sk := os.Getenv("AUTHWARE_SESSION_KEY")
	if sk == "" {
		sk = rand.Text()
	}

	x.sb = securebytes.New(
		[]byte(os.Getenv(sk)),
		securebytes.JSONSerializer{},
	)

	return x, nil
}

// BasicHandler implements the HTTP handler interface.
func (b *BasicMiddleware) BasicHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			slog.Debug("Received request with no auth", "url", r.URL.String())
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "HTTP Basic Authentication Required")
			return
		}

		user, err := b.authByUsernamePassword(r.Context(), u, p)
		if err != nil {
			slog.Debug("Denying request after no auth method matched")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Access Denied")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserKey{}, user)))
	})
}

func (b *BasicMiddleware) authByUsernamePassword(ctx context.Context, user, pass string) (User, error) {
	for _, a := range b.a {
		slog.Debug("Attempting authentication", "mech", a.Name())
		if a.AuthUserPassword(ctx, user, pass) == nil {
			groups, err := a.UserGroups(ctx, user)
			if err != nil {
				slog.Warn("Error while retriving user groups", "error", err)
				groups = make(map[string]struct{})
			}

			usr := User{
				AuthedBy: a.Name(),
				Identity: user,
				Groups:   groups,
			}
			return usr, nil
		}
	}
	return User{}, ErrUnauthenticated{}
}
