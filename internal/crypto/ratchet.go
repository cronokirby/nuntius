package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// rootKey represents the root key used for maintaining our main ratchet.
//
// This key is used to derive new root keys, as well as keys for ratchet chains
// for sending and receiving messages.
type rootKey []byte

// rootKeySize is the number of bytes in a root key
const rootKeySize = 32

// chainKey represents a chain key used for deriving message keys
//
// Chain keys are used to generate message keys with a ratchet.
type chainKey []byte

// chainKeySize is the number of bytes in a chain key
const chainKeySize = 32

var kdfRootKeyInfo = []byte("Nuntius Root Key KDF 2021-06-20")

// kdfRootKey uses a root key, and a shared secret, to derive a new root key, and a chain key
//
// This corresponds to the KDF_RK function.
func kdfRootKey(rk rootKey, dhOut exchangedSecret) (rootKey, chainKey, error) {
	reader := hkdf.New(sha256.New, dhOut, rk, kdfRootKeyInfo)
	rootKey := rootKey(make([]byte, rootKeySize))
	chainKey := chainKey(make([]byte, chainKeySize))
	_, err := io.ReadFull(reader, rootKey)
	if err != nil {
		return nil, nil, err
	}
	_, err = io.ReadFull(reader, chainKey)
	if err != nil {
		return nil, nil, err
	}
	return rootKey, chainKey, nil
}

// messageKey represents a key used for encrypting messages
type MessageKey []byte

// MessageKeySize is the number of bytes in a message key
const MessageKeySize = 32

// kdfChainKey uses a chain key to derive a new chain and message key.
//
// This corresponds to the KDF_CK function
func kdfChainKey(ck chainKey) (chainKey, MessageKey, error) {
	hash := hmac.New(sha256.New, ck)
	_, err := hash.Write([]byte{0})
	if err != nil {
		return nil, nil, err
	}
	ck = chainKey(hash.Sum(nil))

	hash.Reset()
	_, err = hash.Write([]byte{1})
	if err != nil {
		return nil, nil, err
	}
	mk := MessageKey(hash.Sum(nil))

	return ck, mk, nil
}
