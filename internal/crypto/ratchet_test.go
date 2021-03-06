package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKDFRootKey(t *testing.T) {
	rk := make([]byte, rootKeySize)
	_, err := rand.Read(rk)
	if err != nil {
		t.Errorf("couldn't generate root key: %v", err)
		return
	}
	dhOut := make([]byte, 32)
	_, err = rand.Read(dhOut)
	if err != nil {
		t.Errorf("couldn't generate exchanged secret: %v", err)
		return
	}
	newRk, ck, err := kdfRootKey(rk, dhOut)
	if err != nil {
		t.Errorf("couldn't derive root key: %v", err)
		return
	}
	if bytes.Equal(newRk, rk) {
		t.Errorf("derived root key matches root key: %v %v", newRk, rk)
		return
	}
	if bytes.Equal(newRk, ck) {
		t.Errorf("derived root key matches chain key: %v %v", newRk, ck)
		return
	}
}

func TestKDFChainKey(t *testing.T) {
	ck := make([]byte, chainKeySize)
	_, err := rand.Read(ck)
	if err != nil {
		t.Errorf("couldn't generate chain key: %v", err)
		return
	}
	newCk, mk, err := kdfChainKey(ck)
	if err != nil {
		t.Errorf("couldn't derive root key: %v", err)
		return
	}
	if bytes.Equal(newCk, ck) {
		t.Errorf("derived chain key matches chain key: %v %v", newCk, ck)
		return
	}
	if bytes.Equal(newCk, mk) {
		t.Errorf("derived chain key matches message key: %v %v", newCk, mk)
		return
	}
}

func TestRatchetEncryption(t *testing.T) {
	secret := SharedSecret(make([]byte, SharedSecretSize))
	_, err := rand.Read(secret)
	if err != nil {
		t.Errorf("couldn't generate shared secret: %v", err)
		return
	}
	receiverPub, receiverPriv, err := GenerateExchange()
	if err != nil {
		t.Errorf("couldn't generate receiver key pair: %v", err)
		return
	}
	senderRatchet, err := DoubleRatchetFromInitiator(secret, receiverPub)
	if err != nil {
		t.Errorf("couldn't generate sender ratchet: %v", err)
		return
	}
	receiverRatchet := DoubleRatchetFromReceiver(secret, receiverPub, receiverPriv)
	for i := byte(0); i < 100; i++ {
		plaintext := []byte{i, i}
		additional := []byte{i}
		sender, receiver := senderRatchet, receiverRatchet
		if i&0b11 >= 2 {
			sender, receiver = receiver, sender
		}
		ciphertext, err := sender.Encrypt(plaintext, additional)
		if err != nil {
			t.Errorf("couldn't encrypt message: %v", err)
			return
		}
		actual, err := receiver.Decrypt(ciphertext, additional)
		if err != nil {
			t.Errorf("couldn't decrypt message: %v", err)
			return
		}
		if !bytes.Equal(actual, plaintext) {
			t.Errorf("decrypted doesn't match plaintext: %v %v", actual, plaintext)
			return
		}
	}
}
