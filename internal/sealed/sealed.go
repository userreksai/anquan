// Package sealed reads encrypted configuration beside the agent executable.
// Encryption prevents plain-text extraction with strings; it does not stop an
// administrator or a reverse engineer from recovering an executable's key.
package sealed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ConfigAAD separates embedded configuration from other encrypted data formats.
const ConfigAAD = "anqu/embedded-config/v1"

// Config reads only config.age beside the executable, never the working directory.
func Config() ([]byte, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return LoadAge(filepath.Join(filepath.Dir(path), ConfigFilename), embeddedIdentity())
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext using AES-256-GCM and a fresh random nonce. The result
// is nonce || ciphertext || authentication tag. Callers must retain their AAD.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open authenticates and decrypts a result produced by Seal.
func Open(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("encrypted data is truncated")
	}
	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("encrypted data authentication failed")
	}
	return plaintext, nil
}
