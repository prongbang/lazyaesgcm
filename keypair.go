package lazyaesgcm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	Pk string `json:"pk"`
	Sk string `json:"sk"`
}

func NewKeyPair() KeyPair {
	var pk [curve25519.PointSize]byte
	var sk [curve25519.ScalarSize]byte

	rand.Read(sk[:])
	curve25519.ScalarBaseMult(&pk, &sk)

	return KeyPair{
		Pk: hex.EncodeToString(pk[:]),
		Sk: hex.EncodeToString(sk[:]),
	}
}

func (k KeyPair) Exchange(pk string) KeyPair {
	return KeyPair{
		Pk: pk,
		Sk: k.Sk,
	}
}

func (k KeyPair) Secret() (string, error) {
	pk, err1 := hex.DecodeString(k.Pk)
	sk, err2 := hex.DecodeString(k.Sk)
	if err1 != nil || err2 != nil {
		return "", errors.New("key invalid")
	}

	sharedKey, err := curve25519.X25519(sk[:], pk[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sharedKey), err
}
