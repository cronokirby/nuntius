package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

func newAEAD(key SharedKey) (cipher.AEAD, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func (key SharedKey) Encrypt(plaintext, additional []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	out := make([]byte, nonceSize)
	_, err = rand.Read(out)
	if err != nil {
		return nil, err
	}

	out = aead.Seal(out, out, plaintext, additional)

	return out, nil
}

func (key SharedKey) Decrypt(ciphertext, additional []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext doesn't contain nonce")
	}

	out, err := aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], additional)
	if err != nil {
		return nil, err
	}
	return out, nil
}
