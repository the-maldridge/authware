package authware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

// NewBasicAuth returns a basic auth middleware.
func NewBasicAuth() Middleware {
	x := new(BasicMiddleware)

	return x
}

// Handler implements the HTTP handler interface.
func (b *BasicMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			slog.Debug("Received request with no auth", "url", r.URL.String())
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "HTTP Basic Authentication Required")
		}

		for _, a := range b.a {
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
			}
		}
	})
}
