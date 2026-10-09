package sealed

import (
	"bytes"
	"testing"
)

func TestStateEncryptionAndAuthentication(t *testing.T) {
	data := []byte(`{"files":{"/private/path":"PRIVATE_HASH"}}`)
	one, err := SealState(data, "files")
	if err != nil {
		t.Fatal(err)
	}
	two, err := SealState(data, "files")
	if err != nil || bytes.Equal(one, two) || bytes.Contains(one, []byte("PRIVATE_HASH")) || bytes.Contains(one, []byte("/private/path")) {
		t.Fatalf("state is not randomized ciphertext: %v", err)
	}
	plain, err := OpenState(one, "files")
	if err != nil || !bytes.Equal(plain, data) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := OpenState(one, "login"); err == nil {
		t.Fatal("state from another module accepted")
	}
	for name, bad := range map[string][]byte{
		"plaintext": data, "empty": nil, "truncated": one[:len(one)-1],
		"header only": []byte(stateMagic), "appended": append(append([]byte{}, one...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenState(bad, "files"); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
	one[len(one)-1] ^= 1
	if _, err := OpenState(one, "files"); err == nil {
		t.Fatal("tampered state accepted")
	}
}
