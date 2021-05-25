package client

import (
	"crypto/ed25519"
	"database/sql"
	"os"
	"os/user"
	"path"
)

// IdentityPub represents the public part of an identity key.
//
// This is used to uniquely identity a given user as well.
type IdentityPub ed25519.PublicKey

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

// ClientStore represents a store for information local to the client application.
//
// This allows us to store things like a user's personal private keys,
// and other information that's useful for the application.
type ClientStore interface {
	// GetIdentity returns the user's current identity, if any, or an error
	GetIdentity() (IdentityPub, error)
	// SaveIdentity saves an identity key-pair, replacing any existing identity
	SaveIdentity(IdentityPub, IdentityPriv) error
	// RegisterFriend registers a friend by identity, and name
	RegisterFriend(IdentityPub, string) error
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
		public BLOB PRIMARY KEY NOT NULL,
  	private BLOB NOT NULL
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

func (store *clientDatabase) SaveIdentity(pub IdentityPub, priv IdentityPriv) error {
	_, err := store.Exec("DELETE FROM identity;")
	if err != nil {
		return err
	}
	_, err = store.Exec(`
	INSERT INTO identity (public, private) VALUES ($1, $2);
	`, pub, priv)
	if err != nil {
		return err
	}
	return nil
}

func (store *clientDatabase) RegisterFriend(pub IdentityPub, name string) error {
	_, err := store.Exec(`
	INSERT INTO friend (public, name)
	VALUES ($1, $2)
	ON CONFLICT DO UPDATE;
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
