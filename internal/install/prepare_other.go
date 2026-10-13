//go:build !linux

package install

import "io"

// Development platforms retain executable-relative paths and never edit SSH.
func Prepare(path string, _ []string, _ io.Writer) (Preparation, error) {
	return Preparation{Path: path}, nil
}

func lockInstallation(string) (func(), error) { return func() {}, nil }
