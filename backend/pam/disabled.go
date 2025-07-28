//go:build !pam

package pam

import "log/slog"

func init() {
	slog.Info("PAM support not enabled in Authware")
}
