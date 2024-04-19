package lazyaesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
)

const (
	nonceSize = 12
	macSize   = 16
)

type LazyAesGcm interface {
	Encrypt(plaintext string, key []byte) (string, error)
	Decrypt(ciphertext string, key []byte) (string, error)
}

type lazyAesGcm256 struct {
}

func (l *lazyAesGcm256) Encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, nonceSize, nonceSize+len(plaintext)+macSize)
	if _, err := cryptorand.Read(nonce); err != nil {
		return "", err
	}

	aesGcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return "", err
	}

	// Encrypt the message and append the ciphertext to the nonce.
	encrypted := aesGcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return hex.EncodeToString(encrypted), nil
}

func (l *lazyAesGcm256) Decrypt(ciphertext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	encrypted, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Split nonce and ciphertext.
	nonce, cipherBytes := encrypted[:nonceSize], encrypted[nonceSize:]

	aesGcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return "", err
	}

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aesGcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func New() LazyAesGcm {
	return &lazyAesGcm256{}
}
