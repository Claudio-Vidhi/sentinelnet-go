// Package crypto: cifratura AES-GCM delle password apparato e gestione della
// master key (env SENTINELNET_MASTER_KEY in base64, altrimenti file su disco).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
)

type Vault struct {
	aead cipher.AEAD
}

// LoadKey restituisce la master key: da env (base64, 32 byte) oppure dal file
// keyPath, creandolo alla prima esecuzione (0600).
func LoadKey(keyPath string) ([]byte, error) {
	if env := os.Getenv("SENTINELNET_MASTER_KEY"); env != "" {
		key, err := base64.StdEncoding.DecodeString(env)
		if err != nil || len(key) != 32 {
			return nil, errors.New("SENTINELNET_MASTER_KEY: attesa chiave base64 di 32 byte")
		}
		return key, nil
	}
	if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func NewVault(key []byte) (*Vault, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Encrypt: base64(nonce || ciphertext). Stringa vuota resta vuota.
func (v *Vault) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := v.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func (v *Vault) Decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	ns := v.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext troppo corto")
	}
	pt, err := v.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
