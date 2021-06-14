package crypto

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestEncryptionRoundtrip(t *testing.T) {
	keyBytes := make([]byte, SharedKeySize)
	_, err := rand.Read(keyBytes)
	if err != nil {
		t.Errorf("couldn't generate key: %v", err)
		return
	}
	key := SharedKey(keyBytes)
	plaintext := []byte("Hello There!")
	additional := []byte("Additional")

	ciphertext, err := key.Encrypt(plaintext, additional)
	if err != nil {
		t.Errorf("couldn't encrypt data: %v", err)
		return
	}

	plaintextAgain, err := key.Decrypt(ciphertext, additional)
	if err != nil {
		t.Errorf("couldn't decrypt data: %v", err)
		return
	}

	if !bytes.Equal(plaintext, plaintextAgain) {
		t.Error("decryption returned a different result")
		return
	}
}
