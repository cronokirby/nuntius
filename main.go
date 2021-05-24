package main

import (
	"crypto/ed25519"
	"database/sql"

	"encoding/hex"
	"fmt"

	"github.com/alecthomas/kong"
	_ "modernc.org/sqlite"
)

const CLIENT_DATABASE = "./client.db"

type clientDatabase struct {
	db *sql.DB
}

func newClientDatabase() (*clientDatabase, error) {
	db, err := sql.Open("sqlite", CLIENT_DATABASE)
	if err != nil {
		return nil, err
	}
	return &clientDatabase{db}, nil
}

func (db *clientDatabase) setup() error {
	_, err := db.db.Exec(`
	CREATE TABLE IF NOT EXISTS identity (
		public BLOB PRIMARY KEY NOT NULL,
  	private BLOB NOT NULL
	);
	`)
	if err != nil {
		return err
	}
	return nil
}

func (db *clientDatabase) hasIdentity() (bool, error) {
	var count int
	err := db.db.QueryRow("SELECT COUNT(*) FROM identity;").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (db *clientDatabase) saveIdentity(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	_, err := db.db.Exec("DELETE FROM identity;")
	if err != nil {
		return err
	}
	_, err = db.db.Exec(`
	INSERT INTO identity (public, private) VALUES ($1, $2);
	`, pub, priv)
	if err != nil {
		return err
	}
	return nil
}

type GenerateCommand struct {
	Force bool `help:"Overwrite existing identity"`
}

func (cmd *GenerateCommand) Run() error {
	db, err := newClientDatabase()
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}
	err = db.setup()
	if err != nil {
		return err
	}
	hasIdentity, err := db.hasIdentity()
	if err != nil {
		return err
	}
	fmt.Println(hasIdentity)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("couldn't generate identity pair: %w", err)
	}
	err = db.saveIdentity(pub, priv)
	if err != nil {
		return err
	}
	fmt.Printf("nuntiusの公開鍵%s\n", hex.EncodeToString(pub))
	return nil
}

var cli struct {
	Generate GenerateCommand `cmd help:"Generate a new identity pair."`
}

func main() {
	ctx := kong.Parse(&cli)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
