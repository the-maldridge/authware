package ldap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"log/slog"

	"github.com/go-ldap/ldap/v3"

	"github.com/the-maldridge/authware"
)

func init() {
	authware.RegisterFactory("ldap", New)
}

type ldapBackend struct {
	url       string
	base      string
	groupAttr string
	bindTmpl  string
}

// New obtains a new authentication service that uses an LDAP server.
func New() (authware.Authenticator, error) {
	x := ldapBackend{
		url:       os.Getenv("AUTHWARE_LDAP_URL"),
		base:      os.Getenv("AUTHWARE_LDAP_BASEDN"),
		groupAttr: os.Getenv("AUTHWARE_LDAP_GROUPATTR"),
		bindTmpl:  os.Getenv("AUTHWARE_LDAP_BIND_TEMPLATE"),
	}

	if x.url == "" {
		slog.Error("Missing required config value", "key", "AUTHWARE_LDAP_URL")
		return nil, errors.New("must specify AUTHWARE_LDAP_URL")
	}

	if x.base == "" {
		slog.Error("Missing required config value", "key", "AUTHWARE_LDAP_BASEDN")
		return nil, errors.New("must specify AUTHWARE_LDAP_BASEDN")
	}

	if x.bindTmpl == "" {
		slog.Error("Missing required config value", "key", "AUTHWARE_LDAP_BIND_TEMPLATE")
		return nil, errors.New("must specify AUTHWARE_LDAP_BIND_TEMPLATE")
	}

	return &x, nil
}

func (l *ldapBackend) AuthUserPassword(ctx context.Context, user, pass string) error {
	ldc, err := ldap.DialURL(l.url)
	if err != nil {
		slog.Error("Error dialing LDAP server", "error", err)
		return err
	}

	if err := ldc.Bind(fmt.Sprintf(l.bindTmpl, user), pass); err != nil {
		return err
	}
	return nil
}

func (l *ldapBackend) UserGroups(ctx context.Context, user string) (map[string]struct{}, error) {
	ldc, err := ldap.DialURL(l.url)
	if err != nil {
		slog.Error("Error dialing LDAP server", "error", err)
		return nil, err
	}

	searchReq := ldap.NewSearchRequest(
		l.base,                        // BaseDN
		ldap.ScopeWholeSubtree,        // Scope
		ldap.NeverDerefAliases,        // DerefAliases
		1,                             // SizeLimit - We only expect to match exactly one user
		10,                            // TimeLimit
		false,                         // TypesOnly
		fmt.Sprintf("(uid=%s)", user), // Filter - Should match authenticated user
		[]string{l.groupAttr},         // Attributes
		nil,                           // Controls
	)

	res, err := ldc.Search(searchReq)
	if err != nil {
		slog.Error("Error while performing ldap search", "error", err)
		return nil, err
	}

	if len(res.Entries) == 0 {
		slog.Warn("No resultant entity for authenticated user!?", "user", user)

		// Something weird is up, lets bail now.
		return nil, new(authware.ErrUnauthenticated)
	}

	groups := make(map[string]struct{})
	for _, g := range res.Entries[0].GetAttributeValues(l.groupAttr) {
		// This is ugly and not fully correct according to the
		// spec for parsing a DN.  In reality this will work
		// for 99% of use cases, and is easier to reason about
		// what its doing.
		grp := strings.Split(strings.Split(g, ",")[0], "=")[1]
		groups[grp] = struct{}{}
	}
	return groups, nil
}

func (l *ldapBackend) Name() string {
	return "ldap"
}
