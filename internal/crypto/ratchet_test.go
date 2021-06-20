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
	}
	dhOut := make([]byte, 32)
	_, err = rand.Read(dhOut)
	if err != nil {
		t.Errorf("couldn't generate exchanged secret: %v", err)
	}
	newRk, ck, err := kdfRootKey(rk, dhOut)
	if err != nil {
		t.Errorf("couldn't derive root key: %v", err)
	}
	if bytes.Equal(newRk, rk) {
		t.Errorf("derived root key matches root key: %v %v", newRk, rk)
	}
	if bytes.Equal(newRk, ck) {
		t.Errorf("derived root key matches chain key: %v %v", newRk, ck)
	}
}

func TestKDFChainKey(t *testing.T) {
	ck := make([]byte, chainKeySize)
	_, err := rand.Read(ck)
	if err != nil {
		t.Errorf("couldn't generate chain key: %v", err)
	}
	newCk, mk, err := kdfChainKey(ck)
	if err != nil {
		t.Errorf("couldn't derive root key: %v", err)
	}
	if bytes.Equal(newCk, ck) {
		t.Errorf("derived chain key matches chain key: %v %v", newCk, ck)
	}
	if bytes.Equal(newCk, mk) {
		t.Errorf("derived chain key matches message key: %v %v", newCk, mk)
	}
}
