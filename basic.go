package authware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// NewBasicAuth returns a basic auth middleware.
func NewBasicAuth() (Middleware, error) {
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

	return x, nil
}

// Handler implements the HTTP handler interface.
func (b *BasicMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			slog.Debug("Received request with no auth", "url", r.URL.String())
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "HTTP Basic Authentication Required")
			return
		}

		for _, a := range b.a {
			slog.Debug("Attempting authentication", "mech", a.Name())
			if a.AuthUserPassword(r.Context(), u, p) == nil {
				groups, err := a.UserGroups(r.Context(), u)
				if err != nil {
					slog.Warn("Error while retriving user groups", "error", err)
					groups = make(map[string]struct{})
				}

				usr := User{
					AuthedBy: a.Name(),
					Identity: u,
					Groups:   groups,
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserKey{}, usr)))
				return
			}
		}

		// If we've made it this far, none of the handlers
		// above were satisfied so we did not serve the rest
		// of the handler chain.
		slog.Debug("Denying request after no auth method matched")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Access Denied")
	})
}
