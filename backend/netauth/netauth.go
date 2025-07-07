package netauth

import (
	"context"
	"log/slog"

	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netauth/netauth/pkg/netauth"
	"github.com/the-maldridge/authware"
)

func init() {
	authware.RegisterFactory("netauth", New)
}

type netAuthBackend struct {
	nacl *netauth.Client
}

// New obtains a new authentication service that uses the NetAuth
// backend.
func New() (authware.Authenticator, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/netauth/")
	viper.AddConfigPath("$HOME/.netauth")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		slog.Error("Fatal error reading configuration", "error", err)
		return nil, err
	}

	// Grab a client
	c, err := netauth.New()
	if err != nil {
		slog.Error("Error during NetAuth initialization", "error", err)
		return nil, err
	}
	c.SetServiceName("authware")

	x := netAuthBackend{
		nacl: c,
	}

	return &x, nil
}

func (b *netAuthBackend) AuthUserPassword(ctx context.Context, user, pass string) error {
	err := b.nacl.AuthEntity(ctx, user, pass)
	if status.Code(err) != codes.OK {
		return err
	}
	return nil
}

func (b *netAuthBackend) UserGroups(ctx context.Context, user string) (map[string]struct{}, error) {
	groups, err := b.nacl.EntityGroups(ctx, user)
	if status.Code(err) != codes.OK {
		slog.Warn("RPC Error: ", "error", err)
		return nil, err
	}

	out := make(map[string]struct{})
	for _, g := range groups {
		out[g.GetName()] = struct{}{}
	}

	return out, nil
}

func (b *netAuthBackend) Name() string {
	return "netauth"
}
