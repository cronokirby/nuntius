package main

import (
	"crypto/ed25519"
	"database/sql"

	"encoding/hex"
	"fmt"
	"os"

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
		public BLOB PRIMARY KEY,
  	private BLOB
	);
	`)
	if err != nil {
		return err
	}
	return nil
}

func commandGenerateIdentity() error {
	db, err := newClientDatabase()
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}
	err = db.setup()
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("couldn't generate identity pair: %w", err)
	}
	fmt.Printf("nuntiusの公開鍵%s\n", hex.EncodeToString(pub))
	fmt.Printf("nuntiusの秘密鍵%s\n", hex.EncodeToString(priv))
	return nil
}

func main() {
	err := commandGenerateIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %+v\n", err)
		os.Exit(1)
	}
}
