package lazyaesgcm_test

import (
	"testing"

	"github.com/prongbang/lazyaesgcm"
)

func TestKeyPair(t *testing.T) {
	// Generate KeyPair
	clientKp := lazyaesgcm.NewKeyPair()
	serverKp := lazyaesgcm.NewKeyPair()

	// Key Exchange
	serverKx := serverKp.Exchange(clientKp.Pk)
	clientKx := clientKp.Exchange(serverKp.Pk)

	// Shared Key
	serverSharedKey, _ := serverKx.Secret()
	clientSharedKey, _ := clientKx.Secret()

	if serverSharedKey != clientSharedKey {
		t.Errorf("Error %s != %s", serverSharedKey, clientSharedKey)
	}
}
