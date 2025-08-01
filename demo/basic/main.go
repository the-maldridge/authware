package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"

	"github.com/the-maldridge/authware"
	_ "github.com/the-maldridge/authware/backend/htpasswd"
	_ "github.com/the-maldridge/authware/backend/ldap"
	_ "github.com/the-maldridge/authware/backend/netauth"
	_ "github.com/the-maldridge/authware/backend/pam"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// First we setup a new middlware for basic auth
	basic, err := authware.NewAuth()
	if err != nil {
		slog.Error("Could not initialize middleware", "error", err)
		os.Exit(2)
	}

	// Setup a basic webserver
	r := chi.NewRouter()
	s := new(http.Server)

	// Setup a root landing page, and a secure prefix that uses
	// the basic middlware.
	r.Get("/", rootLanding)
	r.Route("/basic", func(r chi.Router) {
		r.Use(basic.BasicHandler)
		r.Get("/", secureLanding)
	})
	r.Get("/login", loginPage)
	r.Post("/login", basic.LoginFormHandler("username", "password", "/logged-in/"))
	r.Route("/logged-in/", func(r chi.Router) {
		r.Use(basic.LoginHandler("/login"))
		r.Get("/", secureLanding)
	})

	r.Route("/multi", func(r chi.Router) {
		r.Use(basic.MultiAuthHandler())
		r.Get("/", secureLanding)
	})

	// Start up the webserver and wait forever.
	go func() {
		s.Handler = r
		s.Addr = ":8000"
		s.ListenAndServe()
	}()
	slog.Info("Demo is running on http://localhost:8000")
	slog.Info("Try loading http://localhost:8000/basic/ for basic auth")
	slog.Info("Try loading http://localhost:8000/logged-in/ for login auth")
	slog.Info("Try loading http://localhost:8000/multi/ for multi-auth matching")
	slog.Info("htpassword credentials", "username", "user", "password", "password")

	// Cleanly shut down the webserver on C-c.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down...")
	if err := s.Shutdown(context.Background()); err != nil {
		slog.Error("Error during shutdown", "error", err)
		os.Exit(2)
	}
}

func rootLanding(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "You've reached the webserver")
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	html := `
<html>
<body>
<form method="post">
Username: <input type="text" name="username" /><br />
Password: <input type="password" name="password" /><br />
<input type="submit" />
</form>
</body>
</html>
`
	w.Write([]byte(html))
}

func secureLanding(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "You're on a secure prefix, this prefix is authenticated")

	user := r.Context().Value(authware.UserKey{}).(authware.User)
	fmt.Fprintf(w, "You are authenticated as '%s' by '%s'\n", user.Identity, user.AuthedBy)
	if len(user.Groups) > 0 {
		fmt.Fprintln(w, "You have membership in the following groups")
	}
	for g := range user.Groups {
		fmt.Fprintf(w, "  * %s\n", g)
	}
}
