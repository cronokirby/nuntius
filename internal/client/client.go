package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/cronokirby/nuntius/internal/server"
	"golang.org/x/crypto/curve25519"
)

// IdentityPub represents the public part of an identity key.
//
// This is used to uniquely identity a given user as well.
type IdentityPub ed25519.PublicKey

const IdentityPubSize = ed25519.PublicKeySize

const _IDENTITY_PUB_HEADER = "nuntiusの公開鍵"

// String returns the string representation of an identity
func (pub IdentityPub) String() string {
	return fmt.Sprintf("%s%s", _IDENTITY_PUB_HEADER, hex.EncodeToString(pub))
}

// IdentityPubFromString attempts to parse an identity from a string, potentially failing
func IdentityPubFromString(s string) (IdentityPub, error) {
	if !strings.HasPrefix(s, _IDENTITY_PUB_HEADER) {
		return nil, errors.New("identity has incorrect header")
	}
	hexString := strings.TrimPrefix(s, _IDENTITY_PUB_HEADER)
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}
	if len(bytes) != IdentityPubSize {
		return nil, fmt.Errorf("decoded identity has incorrect length: %d", len(bytes))
	}
	return IdentityPub(bytes), nil
}

// IdentityPriv represents the private part of an identity key.
//
// This should be kept secret. Leaking this key would allow
// anyone else to impersonate the user with this identity.
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

type ExchangePub []byte

const ExchangePubSize = curve25519.PointSize

type ExchangePriv []byte

// ClientStore represents a store for information local to the client application.
//
// This allows us to store things like a user's personal private keys,
// and other information that's useful for the application.
type ClientStore interface {
	// GetIdentity returns the user's current identity, if any, or an error
	GetIdentity() (IdentityPub, error)
	// GetIdentity returns the user's current identity, and private key, if any, or an error
	GetFullIdentity() (IdentityPub, IdentityPriv, error)
	// SaveIdentity saves an identity key-pair, replacing any existing identity
	SaveIdentity(IdentityPub, IdentityPriv) error
	// AddFriend registers a friend by identity, and name
	AddFriend(IdentityPub, string) error
}

// This will be the path after the Home directory where we put our SQLite database.
const _DEFAULT_DATABASE_PATH = ".nuntius/client.db"

// clientDatabase is used to implement ClientStore over an SQLite database
type clientDatabase struct {
	*sql.DB
}

// newClientDatabase creates a clientDatabase, given a path to an SQLite database
//
// If this path is empty, a default path is used instead, based on the
// current Home directory.
func newClientDatabase(database string) (*clientDatabase, error) {
	if database == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		database = path.Join(usr.HomeDir, _DEFAULT_DATABASE_PATH)
	}
	os.MkdirAll(path.Dir(database), os.ModePerm)
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS identity (
		id BOOLEAN PRIMARY KEY CONSTRAINT one_row CHECK (id) NOT NULL,
		public BLOB NOT NULL,
		private BLOB NOT NULL
	);

	CREATE TABLE IF NOT EXISTS friend (
 		public BLOB PRIMARY KEY NOT NULL,
  	name TEXT NOT NULL
	);
	`)
	if err != nil {
		return nil, err
	}
	return &clientDatabase{db}, nil
}

func (store *clientDatabase) GetIdentity() (IdentityPub, error) {
	var pub IdentityPub
	err := store.QueryRow("SELECT public FROM identity LIMIT 1;").Scan(&pub)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func (store *clientDatabase) GetFullIdentity() (IdentityPub, IdentityPriv, error) {
	var pub IdentityPub
	var priv IdentityPriv
	err := store.QueryRow("SELECT public, private FROM identity LIMIT 1;").Scan(&pub, &priv)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func (store *clientDatabase) SaveIdentity(pub IdentityPub, priv IdentityPriv) error {
	_, err := store.Exec(`
	INSERT OR REPLACE INTO identity (id, public, private) VALUES (true, $1, $2);
	`, pub, priv)
	if err != nil {
		return err
	}
	return nil
}

func (store *clientDatabase) AddFriend(pub IdentityPub, name string) error {
	_, err := store.Exec(`
	INSERT OR REPLACE INTO friend (public, name)
	VALUES ($1, $2);
	`, pub, name)
	return err
}

// NewStore creates a new ClientStore given a path to a local database.
//
// This will create the database file as necessary.
//
// If this string is empty, a default database, placed in the user's Home directory,
// is used instead.
func NewStore(database string) (ClientStore, error) {
	db, err := newClientDatabase(database)
	if err != nil {
		return nil, err
	}
	return db, err
}

type ClientAPI interface {
	// SendPrekey registers a new prekey for this identity, accompanied with a signature
	SendPrekey(identity IdentityPub, prekey ExchangePub, sig []byte) error
}

func NewClientAPI(url string) ClientAPI {
	return &httpClientAPI{url}
}

type httpClientAPI struct {
	root string
}

func (api *httpClientAPI) SendPrekey(identity IdentityPub, prekey ExchangePub, sig []byte) error {
	idBase64 := base64.URLEncoding.EncodeToString(identity)
	data := server.PrekeyRequest{
		Prekey: prekey,
		Sig:    sig,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/prekey/%s", api.root, idBase64), bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok {
		return errors.New(resp.Status)
	}
	return nil
}

func RenewPrekey(api ClientAPI, pub IdentityPub, priv IdentityPriv) (ExchangePub, ExchangePriv, error) {
	scalar := make([]byte, curve25519.ScalarSize)
	_, err := rand.Read(scalar)
	if err != nil {
		return nil, nil, err
	}
	point, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	prekey := ExchangePub(point)
	sig := ed25519.Sign(ed25519.PrivateKey(priv), prekey)

	err = api.SendPrekey(pub, prekey, sig)
	if err != nil {
		return nil, nil, err
	}
	return prekey, ExchangePriv(scalar), nil
}
