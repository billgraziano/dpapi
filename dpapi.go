package dpapi

import (
	"encoding/base64"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

type cryptProtect uint32

const (
	cryptProtectUIForbidden  cryptProtect = 0x1
	cryptProtectLocalMachine cryptProtect = 0x4
)

var (
	dllcrypt32 = windows.NewLazySystemDLL("Crypt32.dll")

	procEncryptData = dllcrypt32.NewProc("CryptProtectData")
	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func (b *dataBlob) zeroMemory() {
	zeros := make([]byte, b.cbData)
	copy((*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:], zeros)
}

func (b *dataBlob) free() error {
	_, err := windows.LocalFree(windows.Handle(unsafe.Pointer(b.pbData)))
	if err != nil {
		return errors.Wrap(err, "localfree")
	}

	return nil
}

// Encrypt a string value to a base64 string
func Encrypt(secret string) (string, error) {
	return encrypt(secret, cryptProtectUIForbidden)
}

func encrypt(secret string, cf cryptProtect) (string, error) {
	var result string
	var b []byte
	b, err := encryptBytes([]byte(secret), cf)
	if err != nil {
		return result, errors.Wrap(err, "encryptbytes")
	}
	result = base64.StdEncoding.EncodeToString(b)
	return result, nil
}

// EncryptBytes encrypts a byte array and returns a byte array
func EncryptBytes(data []byte) ([]byte, error) {
	return encryptBytes(data, cryptProtectUIForbidden)
}

func encryptBytes(data []byte, cf cryptProtect) ([]byte, error) {
	var outblob dataBlob
	r, _, err := procEncryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, errors.Wrap(err, "procencryptdata")
	}

	enc := outblob.toByteArray()
	return enc, outblob.free()
}

// EncryptBytesMachineLocal encrypts a byte array and returns a byte array and associates the data
// encrypted with the current computer instead of with an individual user.
func EncryptBytesMachineLocal(data []byte) ([]byte, error) {
	return encryptBytes(data, cryptProtectUIForbidden|cryptProtectLocalMachine)
}

// EncryptMachineLocal a string value to a base64 string and associates the data encrypted with the
// current computer instead of with an individual user.
func EncryptMachineLocal(secret string) (string, error) {
	return encrypt(secret, cryptProtectUIForbidden|cryptProtectLocalMachine)
}

// DecryptBytes decrypts a byte array returning a byte array
func DecryptBytes(data []byte) ([]byte, error) {
	var outblob dataBlob
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, uintptr(cryptProtectUIForbidden), uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, errors.Wrap(err, "procdecryptdata")
	}

	dec := outblob.toByteArray()
	outblob.zeroMemory()
	return dec, outblob.free()
}

// Decrypt a string to a string
func Decrypt(data string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", errors.Wrap(err, "decodestring")
	}

	b, err := DecryptBytes(raw)
	if err != nil {
		return "", errors.Wrap(err, "decryptbytes")
	}
	return string(b), nil
}
