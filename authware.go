package authware

import (
	"log/slog"
)

var (
	factories map[string]Factory
)

func init() {
	factories = make(map[string]Factory)
}

// RegisterFactory idempotently registers factories for later
// initialization.
func RegisterFactory(s string, f Factory) {
	if _, exists := factories[s]; exists {
		slog.Warn("AuthFactory name collission", "name", s)
		return
	}
	factories[s] = f
	slog.Info("Registered Auth Mechanism", "mechanism", s)
}

// Initialize requests that an authenticator initialize and become
// ready, to be added to one or more middlewares.  This function is
// exposed so that authenticators can be consumed directly outside of
// middlewares.
func Initialize(s string) (Authenticator, error) {
	f, ok := factories[s]
	if !ok {
		slog.Error("Non existant mechanism requested", "mechanism", s)
		return nil, new(ErrDoesNotExist)
	}
	return f()
}
