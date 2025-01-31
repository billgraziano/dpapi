package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/billgraziano/dpapi"
)

// All bytes are stored in hex
var (
	stableString = "Hello World!"
	stableBytes  = "0102030405"
)

// StaticFile is used to read and write a JSON file of staticly encrypted values
type StaticFile struct {
	StableString string `json:"stable_string"`
	StableBytes  string `json:"stable_bytes"`
	UserString   string `json:"user_string"`
	UserBytes    string `json:"user_bytes"`
}

func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() (err error) {
	sf, err := encrypt()
	if err != nil {
		return fmt.Errorf("encrypt: %v", err)
	}

	fileName, err := fileName()
	if err != nil {
		return fmt.Errorf("filename: %v", err)
	}

	// 2. if file doesn't exist, write
	_, err = os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.stat: %v", err)
	}

	// file doesn't exist so write it
	if os.IsNotExist(err) {
		fmt.Printf("writing: %s\n", fileName)
		body, err := json.MarshalIndent(sf, "", "	")
		if err != nil {
			return fmt.Errorf("json.marshalindent: %v", err)
		}

		err = os.WriteFile(fileName, body, 0600)
		if err != nil {
			return fmt.Errorf("os.writefile: %v", err)
		}
	}

	info, err := os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.state: %v", err)
	}

	// 3. read, decrypt, and compare
	fmt.Printf("reading: %s (from %s)\n", fileName, info.ModTime().Format("2006-01-02"))
	stable, err := readFile(fileName)
	if err != nil {
		return fmt.Errorf("readfile: %v", err)
	}

	err = compare(stable, sf)
	if err != nil {
		return fmt.Errorf("compare: %v", err)
	}

	fmt.Println("all fields match")
	return nil
}

func compare(stable StaticFile, new StaticFile) error {
	var err error

	// User String
	str, err := dpapi.Decrypt(stable.UserString)
	if err != nil {
		return fmt.Errorf("dpapi.decrypt: %v", err)
	}
	if str != stableString {
		fmt.Printf("decrypted user string from stable: '%s'  (expected : '%s')\n", str, stableString)
		return errors.New("user string doesn't match")
	}
	fmt.Println("user string matches")

	// User Bytes
	hexVal, err := decryptBytesBase64ToHex(stable.UserBytes)
	if err != nil {
		return fmt.Errorf("decryptbytesbase64tohex: %v", err)
	}
	if hexVal != stableBytes {
		fmt.Printf("decrypted user bytes from stable: '%s'  (expected : '%s')\n", hexVal, stableBytes)
		return errors.New("user bytes don't match")
	}
	fmt.Println("user bytes matches")
	return nil
}

func decryptBytesBase64ToHex(val string) (string, error) {
	bb, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return "", fmt.Errorf("base64.stdencoding.decodestring: %v", err)
	}
	// decrypt bytes
	bb2, err := dpapi.DecryptBytes(bb)
	if err != nil {
		return "", fmt.Errorf("dpapi.decryptbytes: %v", err)
	}
	// encode to hex
	hexVal := hex.EncodeToString(bb2)
	return hexVal, nil
}

func encrypt() (StaticFile, error) {
	var sf StaticFile
	var err error
	sf.StableString = stableString
	sf.StableBytes = stableBytes

	sf.UserString, err = dpapi.Encrypt(stableString)
	if err != nil {
		return sf, fmt.Errorf("dpapi.encrypt: %v", err)
	}

	sf.UserBytes, err = encryptBytesToBase64(stableBytes)
	if err != nil {
		return sf, fmt.Errorf("encryptbytestobase64: %v", err)
	}
	return sf, nil
}

func encryptBytesToBase64(val string) (string, error) {
	bb, err := hex.DecodeString(val)
	if err != nil {
		return "", fmt.Errorf("hex.decodestring: %v", err)
	}
	encryptedBytes, err := dpapi.EncryptBytes(bb)
	if err != nil {
		return "", fmt.Errorf("dpapi.encryptbytes: %v", err)
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func readFile(fileName string) (sf StaticFile, err error) {
	fileName = filepath.Clean(fileName)
	_, err = os.Stat(fileName)
	if err != nil {
		return sf, fmt.Errorf("os.state: %v", err)
	}
	/* #nosec# G304 - fileName cleaned above */
	bb, err := os.ReadFile(fileName)
	if err != nil {
		return sf, fmt.Errorf("os.readfile: %v", err)
	}
	err = json.Unmarshal(bb, &sf)
	if err != nil {
		return sf, fmt.Errorf("json.unmarshal: %v", err)
	}
	return sf, nil
}

func fileName() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("os.getwd: %v", err)
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("os.hostname: %v", err)
	}
	user, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("user.current: %v", err)
	}
	parts := strings.Split(user.Username, "\\")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid user.Current().Username: %s", user.Username)
	}
	domain := parts[0]
	username := parts[1]

	fileName := fmt.Sprintf("%s.%s.%s.stable.json", domain, host, username)
	fileName = filepath.Join(wd, fileName)
	fileName = filepath.Clean(fileName)
	return fileName, nil
}
