// Package cache is the encrypted local cache for results pending upload
// (Blueprint §13.3 encrypted-cache).
package cache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Encrypted struct {
	dir string
	key []byte
}

func NewEncrypted(dir string) (*Encrypted, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, ".cache.key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, err
		}
	}
	if len(key) < 32 {
		return nil, errors.New("agent cache: key too short")
	}
	return &Encrypted{dir: dir, key: key[:32]}, nil
}

func (e *Encrypted) Put(name string, body []byte) error {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, body, nil)
	out := append(nonce, ct...)
	return os.WriteFile(filepath.Join(e.dir, name+".enc"), out, 0o600)
}

func (e *Encrypted) Get(name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(e.dir, name+".enc"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("cache: ciphertext too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}

func (e *Encrypted) Hash(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}
