# lazyaesgcm

Lazy AES-GCM in golang on [golang.org/x/crypto](golang.org/x/crypto).

[![Go Report Card](https://goreportcard.com/badge/github.com/prongbang/lazyaesgcm)](https://goreportcard.com/report/github.com/prongbang/lazyaesgcm)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

### Algorithm details

- Key exchange: X25519
- Encryption: AES
- Authentication: GCM

### Install

```
go get github.com/prongbang/lazyaesgcm
```

### Benchmark

```shell
BenchmarkEncrypt-10    	  876500	      1352 ns/op	    1728 B/op	       9 allocs/op
BenchmarkDecrypt-10    	 1317686	       865.9 ns/op	    1408 B/op	       8 allocs/op
```

### How to use

- Generate KeyPair

```go
keyPair := lazyaesgcm.NewKeyPair()
```

- Key Exchange

```go
clientKp := lazyaesgcm.NewKeyPair()
serverKp := lazyaesgcm.NewKeyPair()

serverKx := serverKp.Exchange(clientKp.Pk)
clientKx := clientKp.Exchange(serverKp.Pk)
```

- Shared Key

```go
serverSharedKey, _ := serverKx.Secret()
clientSharedKey, _ := clientKx.Secret()
```

- Encrypt

```go
lazyAesGcm := lazyaesgcm.New()
sharedKey, _ := clientKx.Secret()
key, _ := hex.DecodeString(sharedKey)
plaintext := "text"
ciphertext, err := lazyAesGcm.Encrypt(plaintext, key)
```

- Decrypt

```go
lazyAesGcm := lazyaesgcm.New()
sharedKey, _ := serverKx.Secret()
key, _ := hex.DecodeString(sharedKey)
ciphertext := "f6a1bd8"
plaintext, err := lazyAesGcm.Decrypt(ciphertext, key)
```
