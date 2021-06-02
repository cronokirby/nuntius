package client

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path"

	"github.com/cronokirby/nuntius/internal/crypto"
	"github.com/cronokirby/nuntius/internal/server"
)

// ClientStore represents a store for information local to the client application.
//
// This allows us to store things like a user's personal private keys,
// and other information that's useful for the application.
type ClientStore interface {
	// GetIdentity returns the user's current identity, if any, or an error
	GetIdentity() (crypto.IdentityPub, error)
	// GetIdentity returns the user's current identity, and private key, if any, or an error
	GetFullIdentity() (crypto.IdentityPub, crypto.IdentityPriv, error)
	// SaveIdentity saves an identity key-pair, replacing any existing identity
	SaveIdentity(crypto.IdentityPub, crypto.IdentityPriv) error
	// AddFriend registers a friend by identity, and name
	AddFriend(crypto.IdentityPub, string) error
	// SavePrekey saves a full prekey pair, possibly failing
	SavePrekey(crypto.ExchangePub, crypto.ExchangePriv) error
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

	CREATE TABLE IF NOT EXISTS prekey (
		public BLOB PRIMARY KEY NOT NULL,
		private BLOB NOT NULL
	);
	`)
	if err != nil {
		return nil, err
	}
	return &clientDatabase{db}, nil
}

func (store *clientDatabase) GetIdentity() (crypto.IdentityPub, error) {
	var pub crypto.IdentityPub
	err := store.QueryRow("SELECT public FROM identity LIMIT 1;").Scan(&pub)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func (store *clientDatabase) GetFullIdentity() (crypto.IdentityPub, crypto.IdentityPriv, error) {
	var pub crypto.IdentityPub
	var priv crypto.IdentityPriv
	err := store.QueryRow("SELECT public, private FROM identity LIMIT 1;").Scan(&pub, &priv)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func (store *clientDatabase) SaveIdentity(pub crypto.IdentityPub, priv crypto.IdentityPriv) error {
	_, err := store.Exec(`
	INSERT OR REPLACE INTO identity (id, public, private) VALUES (true, $1, $2);
	`, pub, priv)
	if err != nil {
		return err
	}
	return nil
}

func (store *clientDatabase) AddFriend(pub crypto.IdentityPub, name string) error {
	_, err := store.Exec(`
	INSERT OR REPLACE INTO friend (public, name)
	VALUES ($1, $2);
	`, pub, name)
	return err
}

func (store *clientDatabase) SavePrekey(pub crypto.ExchangePub, priv crypto.ExchangePriv) error {
	_, err := store.Exec(`
	INSERT OR REPLACE INTO prekey (public, private) VALUES ($1, $2);
	`, pub, priv)
	if err != nil {
		return err
	}
	return nil
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
	SendPrekey(crypto.IdentityPub, crypto.ExchangePub, crypto.Signature) error
	// CountOnetimes asks how many onetime keys this identity has registered with a server
	CountOnetimes(crypto.IdentityPub) (int, error)
}

func NewClientAPI(url string) ClientAPI {
	return &httpClientAPI{url}
}

type httpClientAPI struct {
	root string
}

func (api *httpClientAPI) SendPrekey(identity crypto.IdentityPub, prekey crypto.ExchangePub, sig crypto.Signature) error {
	idBase64 := base64.URLEncoding.EncodeToString(identity)
	data := server.PrekeyRequest{
		Prekey: prekey,
		Sig:    sig,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("%s/prekey/%s", api.root, idBase64), "application/json", bytes.NewBuffer(body))
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

func RenewPrekey(api ClientAPI, pub crypto.IdentityPub, priv crypto.IdentityPriv) (crypto.ExchangePub, crypto.ExchangePriv, error) {
	exchangePub, exchangePriv, err := crypto.GenerateExchange()
	if err != nil {
		return nil, nil, err
	}
	sig := priv.Sign(exchangePub)
	err = api.SendPrekey(pub, exchangePub, sig)
	if err != nil {
		return nil, nil, err
	}
	return exchangePub, exchangePriv, nil
}

func (api *httpClientAPI) CountOnetimes(identity crypto.IdentityPub) (int, error) {
	var count int

	idBase64 := base64.URLEncoding.EncodeToString(identity)
	resp, err := http.Get(fmt.Sprintf("%s/onetime/%s", api.root, idBase64))
	if err != nil {
		return count, err
	}
	defer resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok {
		return count, errors.New(resp.Status)
	}

	var data server.CountOnetimeResponse
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return count, err
	}

	return data.Count, nil
}
