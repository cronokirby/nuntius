package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const ExchangePubSize = curve25519.PointSize

// ExchangePub is the public component of an exchange key
type ExchangePub []byte

// ExchangePriv is the private component of an exchange key
type ExchangePriv []byte

// GenerateExchange creates a new exchange key-pair
//
// This will use a secure source of randomness.
//
// An error may be returned if generation fails.
func GenerateExchange() (ExchangePub, ExchangePriv, error) {
	scalar := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(scalar)
	if err != nil {
		return nil, nil, err
	}

	point, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return ExchangePub(point), ExchangePriv(scalar), nil
}

// ExchangePubFromBytes creates a public exchange key from bytes
//
// This will return an error if the number of bytes is incorrect.
func ExchangePubFromBytes(pubBytes []byte) (ExchangePub, error) {
	if len(pubBytes) != ExchangePubSize {
		return nil, fmt.Errorf("incorrect ExchangePub size: %d", len(pubBytes))
	}
	return ExchangePub(pubBytes), nil
}

// Signature represents a signature over some data with an identity key
type Signature []byte

const IdentityPubSize = ed25519.PublicKeySize

// IdentityPub is the public component of an identity key
//
// This can be used to verify signatures from an identity.
type IdentityPub ed25519.PublicKey

// IdentityPriv is the private component of an identity key
//
// This can be used to generate signatures for an identity.
type IdentityPriv ed25519.PrivateKey

// GenerateIdentity creates a new identity key-pair.
//
// This generates a new key, using a secure source of randomness.
//
// An error may be returned if generation fails.
func GenerateIdentity() (IdentityPub, IdentityPriv, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return IdentityPub(pub), IdentityPriv(priv), nil
}

const identityPubHeader = "nuntiusの公開鍵"

// String returns the string representation of an identity
func (pub IdentityPub) String() string {
	return fmt.Sprintf("%s%s", identityPubHeader, hex.EncodeToString(pub))
}

// IdentityPubFromString attempts to parse an identity from a string, potentially failing
func IdentityPubFromString(s string) (IdentityPub, error) {
	if !strings.HasPrefix(s, identityPubHeader) {
		return nil, errors.New("identity has incorrect header")
	}
	hexString := strings.TrimPrefix(s, identityPubHeader)
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}
	if len(bytes) != IdentityPubSize {
		return nil, fmt.Errorf("decoded identity has incorrect length: %d", len(bytes))
	}
	return IdentityPub(bytes), nil
}

// IdentityPubFromBase64 attempts to convert URL-safe Base64 into a public identity key
//
// This will return an error if decoding fails, or if the number of bytes doesn't
// match the size of a public key.
func IdentityPubFromBase64(data string) (IdentityPub, error) {
	idBytes, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	if len(idBytes) != IdentityPubSize {
		return nil, fmt.Errorf("incorrect IdentityPub length %d", len(idBytes))
	}
	return IdentityPub(idBytes), nil
}

// Sign uses an identity to generate signature for some data
//
// Forging this signature should be impossible without having acess to the private key.
// Anyone with the public part of an identity key can verify the signature.
func (priv IdentityPriv) Sign(data []byte) Signature {
	return ed25519.Sign(ed25519.PrivateKey(priv), data)
}

// Verify uses the public part of an identity to verify a signature on some data
func (pub IdentityPub) Verify(data []byte, sig Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}

// PublicBundle is a collection of single-use exchange keys
type PublicBundle []ExchangePub

// PrivateBundle is a collection of the private counterparts to single-use exchange keys
type PrivateBundle []ExchangePriv

const bundleSize = 64

// GenerateBundle generates a new bundle of exchange keys, possibly failing
func GenerateBundle() (PublicBundle, PrivateBundle, error) {
	publicBundle := make([]ExchangePub, bundleSize)
	privateBundle := make([]ExchangePriv, bundleSize)
	for i := 0; i < bundleSize; i++ {
		pub, priv, err := GenerateExchange()
		if err != nil {
			return nil, nil, err
		}
		publicBundle[i] = pub
		privateBundle[i] = priv
	}
	return publicBundle, privateBundle, nil
}

func (bundle PublicBundle) bytes() []byte {
	data := make([]byte, len(bundle)*ExchangePubSize)
	i := 0
	for _, pub := range bundle {
		copy(data[i:], pub)
		i += ExchangePubSize
	}
	return data
}

// SignBundle uses an identity key to sign a bundle of exchange keys
func (priv IdentityPriv) SignBundle(bundle PublicBundle) Signature {
	return priv.Sign(bundle.bytes())
}

// VerifyBundle verifies a signature generated over a bundle of exchange keys
func (pub IdentityPub) VerifyBundle(bundle PublicBundle, sig Signature) bool {
	return pub.Verify(bundle.bytes(), sig)
}
