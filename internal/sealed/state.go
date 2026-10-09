package sealed

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const stateMagic = "ANQU-STATE\x00\x01"

// IsState identifies the encrypted state container; it does not authenticate it.
func IsState(data []byte) bool { return bytes.HasPrefix(data, []byte(stateMagic)) }

// State uses a separate key derived from the existing deployment identity. No
// plaintext key file is created. Like config.age, this cannot hide data from an
// administrator who can extract the executable's identity.
func stateKey() []byte {
	mac := hmac.New(sha256.New, []byte(embeddedIdentity()))
	mac.Write([]byte("anqu/state-key/v1"))
	return mac.Sum(nil)
}

func SealState(data []byte, kind string) ([]byte, error) {
	key := stateKey()
	defer clear(key)
	ciphertext, err := Seal(key, data, []byte(stateMagic+"\x00"+kind))
	if err != nil {
		return nil, err
	}
	return append([]byte(stateMagic), ciphertext...), nil
}

// OpenState authenticates both the bytes and module identity before parsing.
func OpenState(data []byte, kind string) ([]byte, error) {
	if !IsState(data) {
		return nil, errors.New("state is not encrypted or has an unsupported format")
	}
	key := stateKey()
	defer clear(key)
	return Open(key, data[len(stateMagic):], []byte(stateMagic+"\x00"+kind))
}
