//go:build !linux

package security

import "os"

func fileIdentity(info os.FileInfo) string { return info.Name() }
