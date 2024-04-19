package lazyaesgcm_test

import (
	"encoding/hex"
	"fmt"
	"github.com/prongbang/lazyaesgcm"
	"testing"
)

var lazyAesGcm lazyaesgcm.LazyAesGcm

func init() {
	lazyAesGcm = lazyaesgcm.New()
}

func TestEncrypt(t *testing.T) {
	clientKeyPair := lazyaesgcm.NewKeyPair()
	serverKeyPair := lazyaesgcm.NewKeyPair()
	kxKeyPair := clientKeyPair.Exchange(serverKeyPair.Pk)
	sharedKey, _ := kxKeyPair.Secret()
	key, _ := hex.DecodeString(sharedKey)
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`
	ciphertext, _ := lazyAesGcm.Encrypt(plaintext, key)
	fmt.Println(sharedKey)
	fmt.Println(ciphertext)
}

func TestDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d")
	ciphertext := "84d685b20c1a647d1bdfddd575fe506163e2215142df6494f9430619e24271240bea94340ed26651573fd125328d9b18d63d6f464f0f7024474ac3864fea59f34dbdbfd5119de23985a0c8549440626dae5d54c00c3171b58f084dda82656c34ecf1de4eb11b33b208a52cac97eb78d88987a4cdd79b11a0713857563df328bfbb52d1c0c04ba931ec"
	plaintext, err := lazyAesGcm.Decrypt(ciphertext, key)
	fmt.Println(plaintext, err)
}

func BenchmarkEncrypt(b *testing.B) {
	key, _ := hex.DecodeString("e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d")
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`
	for i := 0; i < b.N; i++ {
		_, err := lazyAesGcm.Encrypt(plaintext, key)
		if err != nil {
			b.Errorf("Error %s", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _ := hex.DecodeString("e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d")
	ciphertext := "84d685b20c1a647d1bdfddd575fe506163e2215142df6494f9430619e24271240bea94340ed26651573fd125328d9b18d63d6f464f0f7024474ac3864fea59f34dbdbfd5119de23985a0c8549440626dae5d54c00c3171b58f084dda82656c34ecf1de4eb11b33b208a52cac97eb78d88987a4cdd79b11a0713857563df328bfbb52d1c0c04ba931ec"
	for i := 0; i < b.N; i++ {
		_, err := lazyAesGcm.Decrypt(ciphertext, key)
		if err != nil {
			b.Errorf("Error %s", err)
		}
	}
}
