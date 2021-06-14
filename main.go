package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cronokirby/nuntius/internal/client"
	"github.com/cronokirby/nuntius/internal/crypto"
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
	pub, priv, err := crypto.GenerateIdentity()
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
	pub, err := crypto.IdentityPubFromString(cmd.Pub)
	if err != nil {
		return err
	}

	store, err := client.NewStore(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}

	return store.AddFriend(pub, cmd.Name)
}

type RegisterCommand struct {
	URL string `arg help:"The URL used to access this server"`
}

func (cmd *RegisterCommand) Run(database string) error {
	store, err := client.NewStore(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}
	pub, priv, err := store.GetFullIdentity()
	if err != nil {
		return err
	}
	if pub == nil {
		fmt.Println("No identity found.")
		fmt.Println("You can use `nuntius generate` to generate an identity.")
		return nil
	}
	api := client.NewClientAPI(cmd.URL)
	xPub, xPriv, err := client.RenewPrekey(api, pub, priv)
	if err != nil {
		return err
	}
	err = store.SavePrekey(xPub, xPriv)
	if err != nil {
		return err
	}
	fmt.Printf("New Prekey registered:\n  %s\n", hex.EncodeToString(xPub))
	newBundle, err := client.CreateNewBundleIfNecessary(api, store, pub, priv)
	if err != nil {
		return err
	}
	if newBundle {
		fmt.Println("New bundle created.")
	}
	return nil
}

type ServerCommand struct {
	Port int `arg help:"The port to use" default:"1234"`
}

func (cmd *ServerCommand) Run(database string) error {
	fmt.Println("Listening on port", cmd.Port)
	server.Run(database, cmd.Port)
	return nil
}

type ChatCommand struct {
	URL  string `arg help:"The URL used to access this server"`
	Name string `arg help:"The name of the friend to chat with"`
}

func (cmd *ChatCommand) Run(database string) error {
	store, err := client.NewStore(database)
	if err != nil {
		return fmt.Errorf("couldn't connect to database: %w", err)
	}

	pub, priv, err := store.GetFullIdentity()
	if err != nil {
		return err
	}
	if pub == nil {
		fmt.Println("No identity found.")
		fmt.Println("You can use `nuntius generate` to generate an identity.")
		return nil
	}

	friendPub, err := store.GetFriend(cmd.Name)
	if err != nil {
		return fmt.Errorf("couldn't lookup friend %s: %w", cmd.Name, err)
	}

	api := client.NewClientAPI(cmd.URL)
	newBundle, err := client.CreateNewBundleIfNecessary(api, store, pub, priv)
	if err != nil {
		return err
	}
	if newBundle {
		fmt.Println("New bundle created.")
	}

	in := make(chan string)
	out, err := client.StartChat(api, store, pub, priv, friendPub, in)
	if err != nil {
		return err
	}
	fmt.Println("Connected.")
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			input, _ := reader.ReadString('\n')
			in <- strings.TrimSuffix(input, "\n")
		}
	}()
	for {
		fmt.Printf("%s> %s\n", cmd.Name, <-out)
	}
}

var cli struct {
	Database string `optional name:"database" help:"Path to local database." type:"path"`

	Generate  GenerateCommand  `cmd help:"Generate a new identity pair."`
	Identity  IdentityCommand  `cmd help:"Fetch the current identity."`
	AddFriend AddFriendCommand `cmd help:"Add a new friend"`
	Register  RegisterCommand  `cmd help:"Register with a server"`
	Server    ServerCommand    `cmd help:"Start a server."`
	Chat      ChatCommand      `cmd help:"Chat with a friend."`
}

func main() {
	ctx := kong.Parse(&cli)
	err := ctx.Run(cli.Database)
	ctx.FatalIfErrorf(err)
}
