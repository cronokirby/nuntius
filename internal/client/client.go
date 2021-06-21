package client

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/cronokirby/nuntius/internal/crypto"
	"github.com/cronokirby/nuntius/internal/server"
	"github.com/gorilla/websocket"
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
	// GetFriend looks up a friend's identity key, using their name
	GetFriend(string) (crypto.IdentityPub, error)
	// SavePrekey saves a full prekey pair, possibly failing
	SavePrekey(crypto.ExchangePub, crypto.ExchangePriv) error
	// SaveBundle saves the public and private parts of a bundle, possibly failing
	SaveBundle(crypto.BundlePub, crypto.BundlePriv) error
	// GetPreKey retrieves the private part of a prekey
	GetPrekey(crypto.ExchangePub) (crypto.ExchangePriv, error)
	// BurnOneTime retrieves a one time key, also deleting it
	BurnOnetime(crypto.ExchangePub) (crypto.ExchangePriv, error)
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

	CREATE TABLE IF NOT EXISTS onetime (
		public BLOB PRIMARY KEY NOT NUll,
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

func (store *clientDatabase) GetFriend(name string) (crypto.IdentityPub, error) {
	var pub crypto.IdentityPub
	err := store.QueryRow("SELECT public FROM friend WHERE name = $1", name).Scan(&pub)
	if err != nil {
		return nil, err
	}
	return pub, nil
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

func (store *clientDatabase) SaveBundle(pub crypto.BundlePub, priv crypto.BundlePriv) error {
	if pub.Len() != len(priv) {
		return fmt.Errorf("public bundle length %d is not equal to private bundle length %d", pub.Len(), len(priv))
	}
	tx, err := store.Begin()
	if err != nil {
		return err
	}
	for i := 0; i < len(priv); i++ {
		_, err := tx.Exec(`
		INSERT INTO onetime (public, private) VALUES ($1, $2);
		`, pub.Get(i), priv[i])
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (store *clientDatabase) GetPrekey(prekey crypto.ExchangePub) (crypto.ExchangePriv, error) {
	var priv crypto.ExchangePriv
	err := store.QueryRow("SELECT private FROM prekey WHERE public = $1;", prekey).Scan(&priv)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (store *clientDatabase) BurnOnetime(pub crypto.ExchangePub) (crypto.ExchangePriv, error) {
	tx, err := store.Begin()
	if err != nil {
		return nil, err
	}
	var priv crypto.ExchangePriv
	err = tx.QueryRow(`
	SELECT private FROM onetime WHERE public = $1 LIMIT 1;
	`, pub).Scan(&priv)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	_, err = tx.Exec("DELETE FROM onetime WHERE public = $1;", pub)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	tx.Commit()
	return priv, nil
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
	// SendBundle sends out a bundle, accompanied with a signature
	SendBundle(crypto.IdentityPub, crypto.BundlePub, crypto.Signature) error
	// CreateSession accesses a new set of exchange keys for a session
	CreateSession(crypto.IdentityPub) (crypto.ExchangePub, crypto.Signature, crypto.ExchangePub, error)
	// Listen starts listening to messages directed towards your public identity
	//
	// This will spawn necssary goroutines to maintain the connection.
	//
	// This takes in a channel which will forward messages you want to send, and returns
	// a channel for receiving incoming messages
	Listen(crypto.IdentityPub, <-chan server.Message) (<-chan server.Message, error)
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
	resp, err := http.Get(fmt.Sprintf("%s/onetime/count/%s", api.root, idBase64))
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

func (api *httpClientAPI) SendBundle(identity crypto.IdentityPub, bundle crypto.BundlePub, sig crypto.Signature) error {
	idBase64 := base64.URLEncoding.EncodeToString(identity)
	data := server.SendBundleRequest{
		Bundle: bundle,
		Sig:    sig,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("%s/onetime/%s", api.root, idBase64), "application/json", bytes.NewBuffer(body))
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

func (api *httpClientAPI) CreateSession(identity crypto.IdentityPub) (crypto.ExchangePub, crypto.Signature, crypto.ExchangePub, error) {
	idBase64 := base64.URLEncoding.EncodeToString(identity)
	resp, err := http.Post(fmt.Sprintf("%s/session/%s", api.root, idBase64), "application/json", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok {
		return nil, nil, nil, errors.New(resp.Status)
	}

	var data server.SessionResponse
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, nil, nil, err
	}

	prekey, err := crypto.ExchangePubFromBytes(data.Prekey)
	if err != nil {
		return nil, nil, nil, err
	}

	onetime, err := crypto.ExchangePubFromBytes(data.OneTime)
	if err != nil {
		return nil, nil, nil, err
	}

	return prekey, data.Sig, onetime, nil
}

const requiredOnetimeSize = 10

func CreateNewBundleIfNecessary(api ClientAPI, store ClientStore, pub crypto.IdentityPub, priv crypto.IdentityPriv) (bool, error) {
	count, err := api.CountOnetimes(pub)
	if err != nil {
		return false, err
	}
	if count >= requiredOnetimeSize {
		return false, nil
	}
	bundlePub, bundlePriv, err := crypto.GenerateBundle()
	if err != nil {
		return false, err
	}
	err = store.SaveBundle(bundlePub, bundlePriv)
	if err != nil {
		return false, err
	}
	sig := priv.SignBundle(bundlePub)
	err = api.SendBundle(pub, bundlePub, sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (api *httpClientAPI) Listen(id crypto.IdentityPub, in <-chan server.Message) (<-chan server.Message, error) {
	wsRoot := strings.TrimPrefix(api.root, "http://")
	idBase64 := base64.URLEncoding.EncodeToString(id)
	dialUrl := url.URL{Scheme: "ws", Host: wsRoot, Path: fmt.Sprintf("/rtc/%s", idBase64)}
	conn, _, err := websocket.DefaultDialer.Dial(dialUrl.String(), nil)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			msg := <-in
			err := conn.WriteJSON(msg)
			if err != nil {
				log.Default().Println(err)
				continue
			}
		}
	}()
	out := make(chan server.Message)
	go func() {
		for {
			var msg server.Message
			err := conn.ReadJSON(&msg)
			if err != nil {
				log.Default().Println(err)
				continue
			}
			out <- msg
		}
	}()
	return out, nil
}

func StartChat(api ClientAPI, store ClientStore, me crypto.IdentityPub, myPriv crypto.IdentityPriv, them crypto.IdentityPub, in <-chan string) (<-chan string, error) {
	inMessage := make(chan server.Message)
	outMessage, err := api.Listen(me, inMessage)
	if err != nil {
		return nil, err
	}
	inMessage <- server.Message{
		From: me,
		To:   them,
		Payload: server.Payload{
			Variant: &server.QueryExchangePayload{},
		},
	}
	var additional []byte
	msg := <-outMessage
	var key crypto.SharedSecret
	switch v := msg.Payload.Variant.(type) {
	case *server.StartExchangePayload:
		additional = append(additional, me...)
		additional = append(additional, them...)

		prekey, err := crypto.ExchangePubFromBytes(v.Prekey)
		if err != nil {
			return nil, err
		}
		if !them.Verify(v.Prekey, v.Sig) {
			return nil, errors.New("couldn't verify prekey signature")
		}
		onetime, err := crypto.ExchangePubFromBytes(v.OneTime)
		if err != nil {
			return nil, err
		}
		ephemeralPub, ephemeralPriv, err := crypto.GenerateExchange()
		if err != nil {
			return nil, err
		}
		key, err = crypto.ForwardExchange(&crypto.ForwardExchangeParams{
			Me:        myPriv,
			Ephemeral: ephemeralPriv,
			Identity:  them,
			Prekey:    prekey,
			OneTime:   onetime,
		})
		if err != nil {
			return nil, err
		}
		inMessage <- server.Message{
			From: me,
			To:   them,
			Payload: server.Payload{
				Variant: &server.EndExchangePayload{
					Prekey:    prekey,
					OneTime:   onetime,
					Ephemeral: ephemeralPub,
				},
			},
		}
	case *server.EndExchangePayload:
		additional = append(additional, them...)
		additional = append(additional, me...)

		ephemeral, err := crypto.ExchangePubFromBytes(v.Ephemeral)
		if err != nil {
			return nil, err
		}

		prekey, err := crypto.ExchangePubFromBytes(v.Prekey)
		if err != nil {
			return nil, err
		}

		onetime, err := crypto.ExchangePubFromBytes(v.OneTime)
		if err != nil {
			return nil, err
		}

		prekeyPriv, err := store.GetPrekey(prekey)
		if err != nil {
			return nil, err
		}

		onetimePriv, err := store.BurnOnetime(onetime)
		if err != nil {
			return nil, err
		}

		key, err = crypto.BackwardExchange(&crypto.BackwardExchangeParams{
			Them:      them,
			Ephemeral: ephemeral,
			Identity:  myPriv,
			Prekey:    prekeyPriv,
			OneTime:   onetimePriv,
		})
		if err != nil {
			return nil, err
		}
	}
	go func() {
		for {
			stringMsg := <-in
			ciphertext, err := key.Encrypt([]byte(stringMsg), additional)
			if err != nil {
				log.Default().Println(err)
				continue
			}
			inMessage <- server.Message{
				From: me,
				To:   them,
				Payload: server.Payload{
					Variant: &server.MessagePayload{Data: ciphertext},
				},
			}
		}
	}()
	out := make(chan string)
	go func() {
		for {
			msg := <-outMessage
			if !bytes.Equal(msg.From, them) {
				continue
			}
			switch v := msg.Payload.Variant.(type) {
			case *server.MessagePayload:
				plaintext, err := key.Decrypt(v.Data, additional)
				if err != nil {
					log.Default().Println(err)
					continue
				}
				out <- string(plaintext)
			}
		}
	}()
	return out, nil
}
