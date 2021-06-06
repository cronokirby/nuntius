package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const ExchangePubSize = curve25519.PointSize
const ExchangeSecretSize = curve25519.PointSize

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

func (priv ExchangePriv) exchange(pub ExchangePub) ([]byte, error) {
	return curve25519.X25519(priv, pub)
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

func (priv IdentityPriv) toExchange() ExchangePriv {
	hash := sha512.New()
	hash.Write(priv[:32])
	digest := hash.Sum(nil)
	return digest[:curve25519.ScalarSize]
}

func (pub IdentityPub) toExchange() (ExchangePub, error) {
	p := new(edwards25519.Point)
	_, err := p.SetBytes(pub)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

// BundlePub is a collection of single-use exchange keys
type BundlePub []byte

// BundlePriv is a collection of the private counterparts to single-use exchange keys
type BundlePriv []ExchangePriv

const bundleSize = 64

// GenerateBundle generates a new bundle of exchange keys, possibly failing
func GenerateBundle() (BundlePub, BundlePriv, error) {
	publicBundle := make([]byte, bundleSize*ExchangePubSize)
	privateBundle := make([]ExchangePriv, bundleSize)
	for i := 0; i < bundleSize; i++ {
		pub, priv, err := GenerateExchange()
		if err != nil {
			return nil, nil, err
		}
		copy(publicBundle[i*ExchangePubSize:], pub)
		privateBundle[i] = priv
	}
	return publicBundle, privateBundle, nil
}

// BundleFromBytes converts a slice of bytes into a public bundle.
//
// This will fail if the length of the data doesn't match an expected length for a bundle.
func BundleFromBytes(data []byte) (BundlePub, error) {
	if len(data)%ExchangePubSize != 0 {
		return nil, errors.New("data is not a multiple of exchange key size")
	}
	return BundlePub(data), nil
}

// Get returns the exchange key at a given index.
//
// This will panic if the index is < 0 or >= bundle.Len().
func (bundle BundlePub) Get(index int) ExchangePub {
	start := index * ExchangePubSize
	stop := start + ExchangePubSize
	return ExchangePub(bundle[start:stop])
}

// Len returns the number of exchange keys in this bundle
func (bundle BundlePub) Len() int {
	return len(bundle) / ExchangePubSize
}

// SignBundle uses an identity key to sign a bundle of exchange keys
func (priv IdentityPriv) SignBundle(bundle BundlePub) Signature {
	return priv.Sign(bundle)
}

// VerifyBundle verifies a signature generated over a bundle of exchange keys
func (pub IdentityPub) VerifyBundle(bundle BundlePub, sig Signature) bool {
	return pub.Verify(bundle, sig)
}

// SharedSecret is derived between two parties, exchanging only public information
type SharedSecret []byte

// SharedSecretSize is the number of bytes in a shared secret
const SharedSecretSize = 32

// ForwardExchangeParams is the information to do an exchange, from a person initiating the exchange
type ForwardExchangeParams struct {
	// The private identity key for the initiator
	me IdentityPriv
	// The private part of an ephemeral exchange key
	ephemeral ExchangePriv
	// The public identity key for the recipient
	identity IdentityPub
	// The signed prekey for the recipient
	prekey ExchangePub
	// The onetime key for the recipient
	onetime ExchangePub
}

var exchangeInfo = []byte("Nuntius X3DH KDF 2021-06-06")

// ForwardExchange performs an exchange with the parameters, deriving a shared secret.
//
// This exchange is used by an initiator, with their private information, to derive
// a shared secret with a recipient, using their public information.
func ForwardExchange(params *ForwardExchangeParams) (SharedSecret, error) {
	meX := params.me.toExchange()
	idX, err := params.identity.toExchange()
	if err != nil {
		return nil, err
	}
	secret := make([]byte, ExchangeSecretSize*4)

	dh1, err := meX.exchange(params.prekey)
	if err != nil {
		return nil, err
	}
	copy(secret, dh1)

	dh2, err := params.ephemeral.exchange(idX)
	if err != nil {
		return nil, err
	}
	copy(secret[ExchangeSecretSize:], dh2)

	dh3, err := params.ephemeral.exchange(params.prekey)
	if err != nil {
		return nil, err
	}
	copy(secret[2*ExchangeSecretSize:], dh3)

	if params.onetime == nil {
		secret = secret[:3*ExchangeSecretSize]
	} else {
		dh4, err := params.ephemeral.exchange(params.onetime)
		if err != nil {
			return nil, err
		}
		copy(secret[3*ExchangeSecretSize:], dh4)
	}

	kdf := hkdf.New(sha512.New, secret, nil, exchangeInfo)
	out := make([]byte, SharedSecretSize)
	_, err = io.ReadFull(kdf, out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// BackwardExchangeParams contains the parameters for an exchange from a recipient
type BackwardExchangeParams struct {
	// The public identity of the initiator
	them IdentityPub
	// The ephemeral key used by the initiator
	ephemeral ExchangePub
	// The private identity of the recipient
	identity IdentityPriv
	// The private prekey of the recipient
	prekey ExchangePriv
	// The private onetime key of the recipient
	onetime ExchangePriv
}

// BackwardExchange derives a shared secret, using the initiators public information
//
// This is the corollary to ForwardExchange, allow the recipient to derive a shared
// secret with an initiator. This is done with the recipient's private information,
// and the initiator's public information.
func BackwardExchange(params *BackwardExchangeParams) (SharedSecret, error) {
	themX, err := params.them.toExchange()
	if err != nil {
		return nil, err
	}
	idX := params.identity.toExchange()

	secret := make([]byte, ExchangeSecretSize*4)

	dh1, err := params.prekey.exchange(themX)
	if err != nil {
		return nil, err
	}
	copy(secret, dh1)

	dh2, err := idX.exchange(params.ephemeral)
	if err != nil {
		return nil, err
	}
	copy(secret[ExchangeSecretSize:], dh2)

	dh3, err := params.prekey.exchange(params.ephemeral)
	if err != nil {
		return nil, err
	}
	copy(secret[2*ExchangeSecretSize:], dh3)

	if params.onetime == nil {
		secret = secret[:3*ExchangeSecretSize]
	} else {
		dh4, err := params.onetime.exchange(params.ephemeral)
		if err != nil {
			return nil, err
		}
		copy(secret[3*ExchangeSecretSize:], dh4)
	}

	kdf := hkdf.New(sha512.New, secret, nil, exchangeInfo)
	out := make([]byte, SharedSecretSize)
	_, err = io.ReadFull(kdf, out)
	if err != nil {
		return nil, err
	}

	return out, nil
}
