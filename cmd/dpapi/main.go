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
	var hexin, str, decrypt string
	flag.StringVar(&hexin, "hex", "", "hex string to encrypt")
	flag.StringVar(&str, "encrypt", "", "string to encrypt")
	flag.StringVar(&decrypt, "decrypt", "", "string to decrypt")
	flag.Parse()

	if hexin == "" && str == "" && decrypt == "" {
		fmt.Println("usage: go run .\\cmd\\dpapi\\main.go -hex 01020304 -encrypt test")
		flag.Usage()
		return
	}
	fmt.Println("")

	if str != "" {
		encrypted, err := dpapi.Encrypt(str)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("'%s' => (string) %s\n\n", str, encrypted)
	}

	if decrypt != "" {
		decrypted, err := dpapi.Decrypt(decrypt)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("decrypted: '%s'\n", decrypted)
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
