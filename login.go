package authware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

// LoginHandler sets up a middleware that handles input from a login
// form and sets a cookie.
func (b *BasicMiddleware) LoginHandler(loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loginURL := url.URL{Path: loginPath}
			nextPath := r.URL.EscapedPath()
			q := loginURL.Query()
			q.Add("next", nextPath)
			loginURL.RawQuery = q.Encode()
			// Check if a cookie exists and if its valid
			var session Session
			cookie, err := r.Cookie("session")
			if err != nil {
				http.Redirect(w, r, loginURL.String(), http.StatusSeeOther)
				return
			}
			if err = b.sb.DecryptBase64(cookie.Value, &session); err != nil {
				http.Redirect(w, r, loginURL.String(), http.StatusSeeOther)
				return
			}
			if time.Now().After(session.Expires) {
				// Session Expired
				http.Redirect(w, r, loginURL.String(), http.StatusSeeOther)
				return
			}

			// Serve the rest of the chain with the user in the
			// request context.
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserKey{}, session.User)))
			return
		})
	}
}

// LogoutHandler clears the cookie and sends the caller somewhere
// else.
func (b *BasicMiddleware) LogoutHandler(nextPath string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &http.Cookie{
			Name:    "session",
			Expires: time.Now().Add(time.Minute * -1),
		}
		http.SetCookie(w, c)
		http.Redirect(w, r, nextPath, http.StatusSeeOther)
	}
}

// LoginFormHandler responds to the form submit and cookies the
// request.
func (b *BasicMiddleware) LoginFormHandler(userField, passField, defaultNext string) func(http.ResponseWriter, *http.Request) {
	duration := os.Getenv("AUTHWARE_SESSION_LIFETIME")
	if duration == "" {
		duration = "1h"
	}
	sessionLifetime, _ := time.ParseDuration(duration)

	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Form must contain %s and %s as fields\n", userField, passField)
			return
		}

		user, err := b.authByUsernamePassword(r.Context(), r.FormValue(userField), r.FormValue(passField))
		if err != nil {
			slog.Debug("Denying request after no auth method matched")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Access Denied")
			return
		}

		session := Session{
			Expires: time.Now().Add(sessionLifetime),
			User:    user,
		}
		b64, err := b.sb.EncryptToBase64(session)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			slog.Error("Error creating cookie", "error", err)
			return
		}
		cookie := &http.Cookie{
			Name:     "session",
			Value:    b64,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(sessionLifetime + time.Minute),
		}
		http.SetCookie(w, cookie)
		next := r.URL.Query().Get("next")
		if next == "" {
			slog.Debug("Default value for next used on login")
			next = defaultNext
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
	}
}
