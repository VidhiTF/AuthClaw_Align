package main

// CBC writing exists only in the test binary to construct historical fixtures.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// EncryptDeterministic constructs legacy AES-CBC ciphertext for migration tests only.
func EncryptDeterministic(plaintext string) (string, error) {
	if encryptionKey == nil {
		initEncryptionKey()
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	h := sha256.New()
	h.Write([]byte(plaintext))
	h.Write(encryptionKey)
	iv := h.Sum(nil)[:aes.BlockSize]

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	combined := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}
