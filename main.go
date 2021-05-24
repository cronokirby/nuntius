package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func commandGenerateIdentity() error {
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
