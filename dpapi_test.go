package dpapi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestString(t *testing.T) {

	secret := "Hello World!;"
	enc, err := Encrypt(secret)
	if err != nil {
		t.Error("err from Encrypt: ", err)
	}
	dec, err := Decrypt(enc)
	if err != nil {
		t.Error("err from Decrypt: ", err)
	}
	if dec != secret {
		t.Errorf("expected: '%s' got: '%s'", secret, dec)
	}
}

func TestBytes(t *testing.T) {

	secret := []byte("Hello World!;")
	enc, err := EncryptBytes(secret)
	if err != nil {
		t.Error("err from EncryptBytes: ", err)
	}
	dec, err := DecryptBytes(enc)
	if err != nil {
		t.Error("err from DecryptBytes: ", err)
	}
	c := bytes.Compare(dec, secret)
	if c != 0 {
		t.Errorf("expected: '%s' got: '%s'", hex.EncodeToString(secret), hex.EncodeToString(dec))
	}
}

func TestMachineLocalString(t *testing.T) {

	secret := "Hello World!;"
	enc, err := EncryptMachineLocal(secret)
	if err != nil {
		t.Error("err from Encrypt: ", err)
	}
	dec, err := Decrypt(enc)
	if err != nil {
		t.Error("err from Decrypt: ", err)
	}
	if dec != secret {
		t.Errorf("expected: '%s' got: '%s'", secret, dec)
	}
}

func TestMachineLocalBytes(t *testing.T) {
	
	secret := []byte("Hello World!;")
	enc, err := EncryptBytesMachineLocal(secret)
	if err != nil {
		t.Error("err from EncryptBytesMachineLocal: ", err)
	}
	dec, err := DecryptBytes(enc)
	if err != nil {
		t.Error("err from DecryptBytes: ", err)
	}
	c := bytes.Compare(dec, secret)
	if c != 0 {
		t.Errorf("expected: '%s' got: '%s'", hex.EncodeToString(secret), hex.EncodeToString(dec))
	}
}