// Author: Tamaaxzcw
// GitHub: https://github.com/Tamaaxzcw

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	ivSize     = 12
	tagSize    = 16
	keySize    = 32 // 256-bit
	iterations = 250000
)

func Encrypt(plainText, secret string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(secret), salt, iterations, keySize, sha512.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	
	// Seal akan menambahkan tag otentikasi secara otomatis
	cipherText := gcm.Seal(nil, iv, []byte(plainText), nil)

	// Gabungkan salt, iv, dan ciphertext
	payload := append(salt, iv...)
	payload = append(payload, cipherText...)

	return base64.StdEncoding.EncodeToString(payload), nil
}

func Decrypt(encryptedPayload, secret string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return "", err
	}

	if len(data) < saltSize+ivSize {
		return "", errors.New("encrypted data is too short")
	}

	salt := data[:saltSize]
	iv := data[saltSize : saltSize+ivSize]
	cipherText := data[saltSize+ivSize:]

	key := pbkdf2.Key([]byte(secret), salt, iterations, keySize, sha512.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plainText, err := gcm.Open(nil, iv, cipherText, nil)
	if err != nil {
		return "", errors.New("decryption failed: " + err.Error())
	}

	return string(plainText), nil
}

func main() {
	secretKey := "tamaaxcw-key"
	originalText := "Pesan ini dienkripsi menggunakan Go!"

	encrypted, err := Encrypt(originalText, secretKey)
	if err != nil {
		panic(err)
	}

	decrypted, err := Decrypt(encrypted, secretKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Original: %s\n", originalText)
	fmt.Printf("Encrypted: %s\n", encrypted)
	fmt.Printf("Decrypted: %s\n", decrypted)
}
