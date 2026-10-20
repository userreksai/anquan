//go:build !linux

package selfupdate

import (
	"context"
	"errors"
	"os"
)

func platformEligible(string) bool        { return false }
func helperEligible(string) bool          { return false }
func ensurePrivateDirectory(string) error { return errors.New("self-update requires Linux systemd") }
func launchHelper(context.Context, string) error {
	return errors.New("self-update requires Linux systemd")
}
func serviceCommand(context.Context, string) error {
	return errors.New("self-update requires Linux systemd")
}
func probeVersion(context.Context, string) ([]byte, error) {
	return nil, errors.New("self-update requires Linux")
}
func syncDirectoryFile(*os.File) error    { return nil }
func privatePermissions(os.FileMode) bool { return true }
func updateHelperActive(string) bool      { return false }
