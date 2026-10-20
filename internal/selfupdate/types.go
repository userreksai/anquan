// Package selfupdate verifies administrator-selected Agent releases and replaces
// the installed executable through a separate, bounded systemd helper.
package selfupdate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxArchiveSize int64 = 128 << 20
const MaxBinarySize int64 = 256 << 20
const InstalledExecutable = "/usr/local/anquan/anquan"
const stateDirectory = "/usr/local/anquan/.self-update"

// SignedFields deliberately uses the same field order as Master. Do not add
// omitempty: its JSON bytes are the signed wire representation.
type SignedFields struct {
	JobID        string `json:"job_id"`
	Version      string `json:"version"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	BinarySHA256 string `json:"binary_sha256"`
	BinarySize   int64  `json:"binary_size"`
	ExpiresAt    string `json:"expires_at"`
	Token        string `json:"token"`
}

type Descriptor struct {
	SignedFields
	Signature string `json:"signature"`
}

type Result struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

var jobPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$`)
var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func parseVersion(version string) ([3]uint64, error) {
	var values [3]uint64
	matches := versionPattern.FindStringSubmatch(version)
	if matches == nil {
		return values, errors.New("Agent version must have three numeric components")
	}
	for i := range values {
		value, err := strconv.ParseUint(matches[i+1], 10, 64)
		if err != nil {
			return values, errors.New("Agent version component is too large")
		}
		values[i] = value
	}
	return values, nil
}

func newer(target, current string) bool {
	a, err := parseVersion(target)
	if err != nil {
		return false
	}
	b, err := parseVersion(current)
	if err != nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func Verify(offer Descriptor, key ed25519.PublicKey, current, goos, goarch string, now time.Time) error {
	if !jobPattern.MatchString(offer.JobID) || !newer(offer.Version, current) {
		return errors.New("invalid update job or target version is not newer")
	}
	if offer.GOOS != "linux" || offer.GOOS != goos || offer.GOARCH != goarch {
		return errors.New("update platform does not match this Agent")
	}
	if offer.Size <= 0 || offer.Size > MaxArchiveSize || offer.BinarySize <= 0 || offer.BinarySize > MaxBinarySize || !validHash(offer.SHA256) || !validHash(offer.BinarySHA256) {
		return errors.New("invalid update size or digest")
	}
	expires, err := time.Parse(time.RFC3339, offer.ExpiresAt)
	if err != nil || !expires.After(now) || expires.After(now.Add(30*time.Minute)) || len(offer.Token) < 32 || len(offer.Token) > 512 {
		return errors.New("update authorization is expired or invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(offer.Signature)
	message, marshalErr := json.Marshal(offer.SignedFields)
	if err != nil || marshalErr != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, signature) {
		return fmt.Errorf("invalid update signature")
	}
	return nil
}
