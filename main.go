package main

import (
	"crypto/ed25519"
	"database/sql"
	"os"
	"os/user"
	"path"

	"encoding/hex"
	"fmt"

	"github.com/alecthomas/kong"
	_ "modernc.org/sqlite"
)

const CLIENT_DATABASE = ".nuntius/client.db"

type clientDatabase struct {
	db *sql.DB
}

func newClientDatabase(database string) (*clientDatabase, error) {
	if database == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		database = path.Join(usr.HomeDir, CLIENT_DATABASE)
	}
	os.MkdirAll(path.Dir(database), os.ModePerm)
	db, err := sql.Open("sqlite", database)
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

func (db *clientDatabase) getIdentity() (ed25519.PublicKey, error) {
	var pub ed25519.PublicKey
	err := db.db.QueryRow("SELECT public FROM identity LIMIT 1;").Scan(&pub)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
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

func (cmd *GenerateCommand) Run(database string) error {
	db, err := newClientDatabase(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}
	err = db.setup()
	if err != nil {
		return err
	}
	existingPub, err := db.getIdentity()
	if err != nil {
		return err
	}
	if existingPub != nil && !cmd.Force {
		fmt.Println("An existing identity exists:")
		fmt.Printf("nuntiusの公開鍵%s\n\n", hex.EncodeToString(existingPub))
		fmt.Println("Use `--force` if you want to overwrite this identity.")
		return nil
	}
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

type IdentityCommand struct {
}

func (cmd *IdentityCommand) Run(database string) error {
	db, err := newClientDatabase(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}
	err = db.setup()
	if err != nil {
		return err
	}

	pub, err := db.getIdentity()
	if err != nil {
		return err
	}
	if pub == nil {
		fmt.Println("No identity found.")
		fmt.Println("You can use `nuntius generate` to generate an identity.")
		return nil
	}
	fmt.Printf("nuntiusの公開鍵%s\n", hex.EncodeToString(pub))
	return nil
}

var cli struct {
	Database string `optional name:"database" help:"Path to local database." type:"path"`

	Generate GenerateCommand `cmd help:"Generate a new identity pair."`
	Identity IdentityCommand `cmd help:"Fetch the current identity."`
}

func main() {
	ctx := kong.Parse(&cli)
	err := ctx.Run(cli.Database)
	ctx.FatalIfErrorf(err)
}
