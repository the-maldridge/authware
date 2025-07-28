//go:build pam

package pam

import (
	"context"
	"log/slog"
	"os"
	"os/user"

	"github.com/msteinert/pam/v2"

	"github.com/the-maldridge/authware"
)

type pamBackend struct {
	svc string
}

func init() {
	authware.RegisterFactory("pam", New)
}

// New can be used to get a new instance of this backend.
func New() (authware.Authenticator, error) {
	p := new(pamBackend)
	p.svc = os.Getenv("AUTHWARE_PAM_SERVICE")
	if p.svc == "" {
		// If the service wasn't set, go for passwd.  This one
		// usually only requires pam_unix.so, and is generally
		// present in all sane PAM configurations.
		p.svc = "passwd"
	}

	return p, nil
}

func (p *pamBackend) AuthUserPassword(ctx context.Context, user, pass string) error {
	t, err := pam.StartFunc(p.svc, user, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return pass, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", new(authware.ErrBackendInternal)
	})
	if err != nil {
		return err
	}

	if err = t.Authenticate(0); err != nil {
		slog.Debug("PAM declined to auth user", "user", user, "error", err)
		return new(authware.ErrUnauthenticated)
	}

	if err = t.AcctMgmt(0); err != nil {
		slog.Debug("PAM declined account management", "user", user, "error", err)
		return new(authware.ErrUnauthenticated)
	}

	return nil
}

func (p *pamBackend) UserGroups(ctx context.Context, userName string) (map[string]struct{}, error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return nil, err
	}
	gIDs, err := u.GroupIds()
	if err != nil {
		return nil, err
	}

	out := make(map[string]struct{})
	for _, gid := range gIDs {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			return nil, err
		}
		out[g.Name] = struct{}{}
	}
	return out, nil
}

func (p *pamBackend) Name() string {
	return "pam"
}
