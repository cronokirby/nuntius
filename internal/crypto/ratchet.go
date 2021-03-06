package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
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

// DoubleRatchet holds the state used for the Diffie Hellman double ratchet.
//
// This will be setup based on the exchange to derive a secret, and then
// updated as messages arrive.
type DoubleRatchet struct {
	// sendingPub is our current exchange public key
	sendingPub ExchangePub
	// sendingPriv is our current exchange private key
	sendingPriv ExchangePriv
	// receivingPub is our correspondant's current public key
	receivingPub ExchangePub
	// rootKey is the current rootKey for the main ratchet
	rootKey rootKey
	// sendingKey is the current chain key for the sending ratchet
	sendingKey chainKey
	// receivingKey is the current chain key for the receiving ratchet
	receivingKey chainKey
}

// DoubleRatchetFromInitiator creates a double ratchet, with information by the initiator of an exchange.
//
// The parameters passed by this function should be known to the initiator of an X3DH exchange.
//
// The receivingPub should be the signed prekey.
func DoubleRatchetFromInitiator(secret SharedSecret, receivingPub ExchangePub) (ratchet DoubleRatchet, err error) {
	ratchet.receivingPub = receivingPub
	ratchet.sendingPub, ratchet.sendingPriv, err = GenerateExchange()
	if err != nil {
		return ratchet, err
	}
	exchanged, err := ratchet.sendingPriv.exchange(receivingPub)
	if err != nil {
		return ratchet, err
	}
	ratchet.rootKey, ratchet.sendingKey, err = kdfRootKey(rootKey(secret), exchanged)
	if err != nil {
		return ratchet, err
	}
	return ratchet, nil
}

// DoubleRatchetFromReceiver creates a double ratchet, with information from the receiver of an exchange.
//
// We use the shared secret we've derived from an exchange, as well as our signed prekey.
func DoubleRatchetFromReceiver(secret SharedSecret, pub ExchangePub, priv ExchangePriv) DoubleRatchet {
	var ratchet DoubleRatchet
	ratchet.sendingPub = pub
	ratchet.sendingPriv = priv
	ratchet.rootKey = rootKey(secret)
	return ratchet
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

// Encrypt uses the current state of the ratchet to encrypt a piece of data.
func (ratchet *DoubleRatchet) Encrypt(plaintext, additional []byte) ([]byte, error) {
	newSendingKey, messageKey, err := kdfChainKey(ratchet.sendingKey)
	if err != nil {
		return nil, err
	}
	ratchet.sendingKey = newSendingKey

	header := []byte(ratchet.sendingPub)

	ciphertext, err := messageKey.Encrypt(plaintext, concat(header, additional))
	if err != nil {
		return nil, err
	}
	return concat(header, ciphertext), nil
}

// Decrypt uses the current state of the ratchet to decrypt a piece of data.
//
// The ciphertext will contain the necessary headers.
//
// This will also advance the state of the ratchet accordingly.
func (ratchet *DoubleRatchet) Decrypt(ciphertext, additional []byte) ([]byte, error) {
	if len(ciphertext) < ExchangePubSize {
		return nil, errors.New("ciphertext does not contain public key")
	}
	header := ciphertext[:ExchangePubSize]
	attachedPub := ExchangePub(header[:ExchangePubSize])
	if !bytes.Equal(attachedPub, ratchet.receivingPub) {
		ratchet.receivingPub = attachedPub
		receivingExchange, err := ratchet.sendingPriv.exchange(ratchet.receivingPub)
		if err != nil {
			return nil, err
		}
		ratchet.rootKey, ratchet.receivingKey, err = kdfRootKey(ratchet.rootKey, receivingExchange)
		if err != nil {
			return nil, err
		}
		ratchet.sendingPub, ratchet.sendingPriv, err = GenerateExchange()
		if err != nil {
			return nil, err
		}
		sendingExchange, err := ratchet.sendingPriv.exchange(ratchet.receivingPub)
		if err != nil {
			return nil, err
		}
		ratchet.rootKey, ratchet.sendingKey, err = kdfRootKey(ratchet.rootKey, sendingExchange)
		if err != nil {
			return nil, err
		}
	}
	ciphertext = ciphertext[ExchangePubSize:]
	newReceivingKey, messageKey, err := kdfChainKey(ratchet.receivingKey)
	if err != nil {
		return nil, err
	}
	ratchet.receivingKey = newReceivingKey
	plaintext, err := MessageKey(messageKey).Decrypt(ciphertext, concat(header, additional))
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
