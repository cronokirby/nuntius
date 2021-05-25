package client

import (
	"crypto/ed25519"
	"database/sql"
	"os"
	"os/user"
	"path"
)

type IdentityPub ed25519.PublicKey

type IdentityPriv ed25519.PrivateKey

func GenerateIdentity() (IdentityPub, IdentityPriv, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return IdentityPub(pub), IdentityPriv(priv), nil
}

type ClientStore interface {
	GetIdentity() (IdentityPub, error)
	SaveIdentity(IdentityPub, IdentityPriv) error
}

const _DEFAULT_DATABASE_PATH = ".nuntius/client.db"

type clientDatabase struct {
	*sql.DB
}

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

func NewStore(database string) (ClientStore, error) {
	db, err := newClientDatabase(database)
	if err != nil {
		return nil, err
	}
	return db, err
}
