package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptionRoundtrip(t *testing.T) {
	key := MessageKey(make([]byte, MessageKeySize))
	_, err := rand.Read(key)
	if err != nil {
		t.Errorf("couldn't generate key: %v", err)
		return
	}
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
