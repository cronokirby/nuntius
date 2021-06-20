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
	if bytes.Equal(ck, rk) {
		t.Errorf("chain key matches root key: %v %v", ck, rk)
	}
}
