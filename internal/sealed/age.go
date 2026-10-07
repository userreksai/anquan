package sealed

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const ConfigFilename = "config.age"
const MaxConfigBytes = 4 << 20
const maxEncryptedBytes = 6 << 20

// EncryptConfig uses the built-in deployment pair, including for optional build output.
func EncryptConfig(data []byte) ([]byte, error) {
	identity, err := age.ParseX25519Identity(embeddedIdentity())
	if err != nil {
		return nil, errors.New("invalid built-in age identity")
	}
	return EncryptAge(data, identity.Recipient())
}

// LoadAge authenticates the whole file before returning any plaintext.
func LoadAge(path, secret string) ([]byte, error) {
	identity, err := age.ParseX25519Identity(strings.TrimSpace(secret))
	if err != nil {
		return nil, errors.New("agent has no valid embedded age identity; rebuild with anqu-build")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open config.age beside agent")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxEncryptedBytes {
		return nil, errors.New("config.age must be a regular file no larger than 6 MiB")
	}
	ciphertext, err := io.ReadAll(io.LimitReader(f, maxEncryptedBytes+1))
	if err != nil || len(ciphertext) > maxEncryptedBytes {
		return nil, errors.New("cannot read config.age")
	}
	ciphertext = bytes.TrimSpace(bytes.TrimPrefix(ciphertext, []byte{0xef, 0xbb, 0xbf}))
	reader, err := age.Decrypt(armor.NewReader(bytes.NewReader(ciphertext)), identity)
	if err != nil {
		return nil, errors.New("config.age decryption failed; check matching agent public key")
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil || len(data) > MaxConfigBytes || len(bytes.TrimSpace(data)) == 0 {
		clear(data)
		return nil, errors.New("config.age is damaged, empty or too large")
	}
	return data, nil
}

// EncryptAge produces the ASCII armor format accepted by the management UI.
func EncryptAge(data []byte, recipient *age.X25519Recipient) ([]byte, error) {
	var out bytes.Buffer
	armored := armor.NewWriter(&out)
	w, err := age.Encrypt(armored, recipient)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(data); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	if err = armored.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
