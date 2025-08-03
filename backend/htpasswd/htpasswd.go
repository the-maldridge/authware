package htpasswd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tg123/go-htpasswd"

	"github.com/the-maldridge/authware"
)

var (
	htpasswdFile string
	htgroupFile  string
)

type htpasswdBackend struct {
	f *htpasswd.File
	g *htpasswd.HTGroup
}

func init() {
	htpasswdFile = os.Getenv("AUTHWARE_HTPASSWD_FILE")
	if htpasswdFile == "" {
		htpasswdFile = ".htpasswd"
	}

	htgroupFile = os.Getenv("AUTHWARE_HTGROUP_FILE")
	if htgroupFile == "" {
		htgroupFile = ".htgroup"
	}

	authware.RegisterFactory("htpasswd", New)
}

// New can be used to get a new instance of this backend
func New() (authware.Authenticator, error) {
	f, err := htpasswd.New(htpasswdFile, htpasswd.DefaultSystems, nil)
	if err != nil {
		return nil, err
	}

	g, err := htpasswd.NewGroups(htgroupFile, nil)
	if err != nil {
		return nil, err
	}

	x := htpasswdBackend{
		f: f,
		g: g,
	}

	rChan := make(chan os.Signal, 1)
	signal.Notify(rChan, syscall.SIGHUP)

	go func() {
		for {
			<-rChan
			if err := f.Reload(nil); err != nil {
				slog.Warn("Error reloading htpasswd", "error", err)
			}
			if err := g.ReloadGroups(nil); err != nil {
				slog.Warn("Error reloading htgroup", "error", err)
			}
			slog.Info("Reloaded htpasswd and htgroup")
		}
	}()

	slog.Info("Initialized", "htpasswd", htpasswdFile, "htgroup", htgroupFile)
	return &x, nil
}
func (h *htpasswdBackend) AuthUserPassword(ctx context.Context, user, pass string) error {
	if !h.f.Match(user, pass) {
		slog.Debug("User unauthenticated", "user", user)
		return new(authware.ErrUnauthenticated)
	}

	return nil
}

func (h *htpasswdBackend) UserGroups(ctx context.Context, user string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	for _, g := range h.g.GetUserGroups(user) {
		out[g] = struct{}{}
	}
	return out, nil
}

func (h *htpasswdBackend) Name() string {
	return "htpasswd"
}
