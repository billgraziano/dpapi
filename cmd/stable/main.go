package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/billgraziano/dpapi"
	"github.com/dustin/go-humanize"

	"github.com/pkg/errors"
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
		return errors.Wrap(err, "encrypt")
	}

	fileName, err := fileName()
	if err != nil {
		return errors.Wrap(err, "filename")
	}

	// 2. if file doesn't exist, write and exit
	info, err := os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "os.stat-1")
	}

	// file doesn't exist so write it
	if os.IsNotExist(err) {
		fmt.Printf("writing: %s\n", fileName)
		body, err := json.MarshalIndent(sf, "", "	")
		if err != nil {
			return errors.Wrap(err, "json.marshalindent")
		}

		err = ioutil.WriteFile(fileName, body, 0700)
		if err != nil {
			return errors.Wrap(err, "ioutil.writefile")
		}
	}

	info, err = os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "os.stat-2")
	}

	// 3. read, decrypt, and compare
	fmt.Printf("reading: %s (%v)\n", fileName, humanize.Time(info.ModTime()))
	stable, err := readFile(fileName)
	if err != nil {
		return errors.Wrap(err, "decrypt")
	}

	err = compare(stable, sf)
	if err != nil {
		return errors.Wrap(err, "compare")
	}

	fmt.Println("all fields match")
	return nil
}

func compare(stable StaticFile, new StaticFile) error {
	var err error

	// User String
	str, err := dpapi.Decrypt(stable.UserString)
	if err != nil {
		errors.Wrap(err, "user.string: dpapi.decrypt")
	}
	if str != stableString {
		fmt.Printf("decrypted user string from stable: '%s'  (expected : '%s')\n", str, stableString)
		return errors.New("user string doesn't match")
	}
	fmt.Println("user string matches")

	// User Bytes
	hexVal, err := decryptBytesBase64ToHex(stable.UserBytes)
	if err != nil {
		return errors.Wrap(err, "user.bytes")
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
		return "", errors.Wrap(err, "base64.stdencoding.decodestring")
	}
	// decrypt bytes
	bb2, err := dpapi.DecryptBytes(bb)
	if err != nil {
		return "", errors.Wrap(err, "dpapi.decryptbytes")
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
		return sf, errors.Wrap(err, "dpapi.encrypt")
	}

	sf.UserBytes, err = encryptBytesToBase64(stableBytes)
	return sf, nil
}

func encryptBytesToBase64(val string) (string, error) {
	bb, err := hex.DecodeString(val)
	if err != nil {
		return "", errors.Wrap(err, "hex.decodestring")
	}
	encryptedBytes, err := dpapi.EncryptBytes(bb)
	if err != nil {
		return "", errors.Wrap(err, "dpapi.encryptbytes")
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func readFile(fileName string) (sf StaticFile, err error) {
	_, err = os.Stat(fileName)
	if err != nil {
		return sf, errors.Wrap(err, "os.stat")
	}
	bb, err := ioutil.ReadFile(fileName)
	if err != nil {
		return sf, errors.Wrap(err, "ioutil.readfile")
	}
	err = json.Unmarshal(bb, &sf)
	if err != nil {
		return sf, errors.Wrap(err, "json.unmarshal")
	}
	return sf, nil
}

func fileName() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", errors.Wrap(err, "os.getwd")
	}
	host, err := os.Hostname()
	if err != nil {
		return "", errors.Wrap(err, "os.hostname")
	}
	user, err := user.Current()
	if err != nil {
		return "", errors.Wrap(err, "user.current")
	}
	parts := strings.Split(user.Username, "\\")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid user.Current().Username: %s", user.Username)
	}
	domain := parts[0]
	username := parts[1]

	fileName := fmt.Sprintf("%s.%s.%s.stable.json", domain, host, username)
	fileName = filepath.Join(wd, fileName)
	return fileName, nil
}
