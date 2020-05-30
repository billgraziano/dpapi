package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/billgraziano/dpapi"
)

// go run .\cmd\dpapi\main.go -hex 01020304 -string junk
func main() {
	var hexin, str string
	flag.StringVar(&hexin, "hex", "01020304", "hex string to encrypt")
	flag.StringVar(&str, "string", "test", "string to encrypt")
	flag.Parse()

	if hexin == "" && str == "" {
		fmt.Println("usage: go run .\\cmd\\dpapi\\main.go -hex 01020304 -string test")
		return
	}
	fmt.Println("")

	if str != "" {
		encrypted, err := dpapi.Encrypt(str)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\"%s\" => (string) %s\n\n", str, encrypted)
	}

	if hexin != "" {
		bb, err := hex.DecodeString(hexin)
		if err != nil {
			log.Fatal(err)
		}
		encrypted, err := dpapi.EncryptBytes(bb)
		if err != nil {
			log.Fatal(err)
		}
		hexout := hex.EncodeToString(encrypted)
		fmt.Printf("0x%s => (hex) 0x%s\n\n", hexin, hexout)

		b64 := base64.StdEncoding.EncodeToString(encrypted)
		fmt.Printf("0x%s => (base64) %s\n\n", hexin, b64)
	}
}
