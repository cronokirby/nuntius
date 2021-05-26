package main

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/cronokirby/nuntius/internal/client"
	"github.com/cronokirby/nuntius/internal/server"
	_ "modernc.org/sqlite"
)

type GenerateCommand struct {
	Force bool `help:"Overwrite existing identity"`
}

func (cmd *GenerateCommand) Run(database string) error {
	store, err := client.NewStore(database)
	if err != nil {
		return fmt.Errorf("couldn't open database: %w", err)
	}
	existingPub, err := store.GetIdentity()
	if err != nil {
		return err
	}
	if existingPub != nil && !cmd.Force {
		fmt.Println("An existing identity exists:")
		fmt.Println(existingPub.String())
		fmt.Println("Use `--force` if you want to overwrite this identity.")
		return nil
	}
	pub, priv, err := client.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("couldn't generate identity pair: %w", err)
	}
	err = store.SaveIdentity(pub, priv)
	if err != nil {
		return err
	}
	fmt.Println(pub.String())
	return nil
}

type IdentityCommand struct {
}

func (cmd *IdentityCommand) Run(database string) error {
	store, err := client.NewStore(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}

	pub, err := store.GetIdentity()
	if err != nil {
		return err
	}
	if pub == nil {
		fmt.Println("No identity found.")
		fmt.Println("You can use `nuntius generate` to generate an identity.")
		return nil
	}
	fmt.Println(pub.String())
	return nil
}

type AddFriendCommand struct {
	Name string `arg help:"The name of the friend"`
	Pub  string `arg help:"Their public identity key"`
}

func (cmd *AddFriendCommand) Run(database string) error {
	pub, err := client.IdentityPubFromString(cmd.Pub)
	if err != nil {
		return err
	}

	store, err := client.NewStore(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}

	return store.AddFriend(pub, cmd.Name)
}

type ServerCommand struct {
	Port int `arg help:"The port to use" default:"1234"`
}

func (cmd *ServerCommand) Run(database string) error {
	fmt.Println("Listening on port", cmd.Port)
	server.Run(cmd.Port)
	return nil
}

var cli struct {
	Database string `optional name:"database" help:"Path to local database." type:"path"`

	Generate  GenerateCommand  `cmd help:"Generate a new identity pair."`
	Identity  IdentityCommand  `cmd help:"Fetch the current identity."`
	AddFriend AddFriendCommand `cmd help:"Add a new friend"`
	Server    ServerCommand    `cmd help:"Start a server."`
}

func main() {
	ctx := kong.Parse(&cli)
	err := ctx.Run(cli.Database)
	ctx.FatalIfErrorf(err)
}
