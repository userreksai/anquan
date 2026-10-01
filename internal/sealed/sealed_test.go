package sealed

import (
	"bytes"
	"testing"
)

func TestConfigWithoutBuildPayload(t *testing.T) {
	if _, err := Config(); err == nil {
		t.Fatal("unconfigured agent must not accept a runtime config fallback")
	}
}

func TestEncryptionAuthenticatedAndRandomized(t *testing.T) {
	key := bytes.Repeat([]byte{0x1f}, 32)
	plaintext := []byte("output_dir: /private/target\n")
	aad := []byte(ConfigAAD)
	one, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one, two) {
		t.Fatal("two seals must have independent random nonces")
	}
	if bytes.Contains(one, plaintext) {
		t.Fatal("plaintext exposed in encrypted data")
	}
	decoded, err := Open(key, one, aad)
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("roundtrip = %q, %v", decoded, err)
	}
	for name, tc := range map[string]struct{ key, ciphertext, aad []byte }{
		"wrong key":     {bytes.Repeat([]byte{0x20}, 32), one, aad},
		"wrong context": {key, one, []byte("other-format")},
		"truncated":     {key, one[:10], aad},
		"short key":     {key[:16], one, aad},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(tc.key, tc.ciphertext, tc.aad); err == nil {
				t.Fatal("unauthenticated data accepted")
			}
		})
	}
	for _, offset := range []int{0, 12, len(one) - 1} {
		tampered := bytes.Clone(one)
		tampered[offset] ^= 1
		if _, err := Open(key, tampered, aad); err == nil {
			t.Fatalf("tampering accepted at byte %d", offset)
		}
	}
	if _, err := Seal(key[:16], plaintext, aad); err == nil {
		t.Fatal("short encryption key accepted")
	}
}
