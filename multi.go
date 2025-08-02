package authware

import (
	"log/slog"
	"net/http"
)

// MultiAuthHandler tries to find a valid scheme and then perform auth
// using a given middleware.
func (b *BasicMiddleware) MultiAuthHandler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := r.BasicAuth(); ok {
				slog.Debug("Basic Auth supplied")
				b.BasicHandler(next).ServeHTTP(w, r)
				return
			}
			if _, err := r.Cookie("session"); err == nil {
				slog.Debug("Cookie Auth supplied")
				b.cookieHandler(next).ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		})
	}
}
