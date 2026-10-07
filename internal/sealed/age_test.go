package sealed

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestExternalAgeConfiguration(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("# 配置注释\noutput_dir: output\nlogin:\n  enabled: false\n")
	one, err := EncryptAge(data, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	two, err := EncryptAge(data, id.Recipient())
	if err != nil || bytes.Equal(one, two) || bytes.Contains(one, []byte("output_dir")) {
		t.Fatal("encryption must be randomized and hide plaintext")
	}
	path := filepath.Join(t.TempDir(), ConfigFilename)
	if err := os.WriteFile(path, append([]byte("\xef\xbb\xbf"), one...), 0600); err != nil {
		t.Fatal(err)
	}
	decoded, err := LoadAge(path, id.String())
	if err != nil || !bytes.Equal(decoded, data) {
		t.Fatalf("roundtrip: %v", err)
	}
	wrong, _ := age.GenerateX25519Identity()
	if _, err := LoadAge(path, wrong.String()); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, bad := range [][]byte{data, one[:len(one)/2], []byte(""), []byte(strings.Repeat("x", maxEncryptedBytes+1))} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if decoded, err := LoadAge(path, id.String()); err == nil || decoded != nil {
			t.Fatal("invalid input returned plaintext")
		}
	}
	if _, err := LoadAge(filepath.Join(t.TempDir(), ConfigFilename), id.String()); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := LoadAge(t.TempDir(), id.String()); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestAgeReloadsChangedConfiguration(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	path := filepath.Join(t.TempDir(), ConfigFilename)
	for _, text := range []string{"output_dir: first\n", "output_dir: second\n"} {
		ciphertext, err := EncryptAge([]byte(text), id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, ciphertext, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadAge(path, id.String())
		if err != nil || string(got) != text {
			t.Fatalf("replacement not loaded: %v", err)
		}
	}
}

func TestFixedDeploymentPairEncryptsExternalConfiguration(t *testing.T) {
	data := []byte("output_dir: external\n")
	ciphertext, err := EncryptConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), ConfigFilename)
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAge(path, embeddedIdentity())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("built-in pair mismatch: %v", err)
	}
}
