package crypt

import (
	"bytes"
	"testing"
)

func TestEncryption(t *testing.T) {
	data := []byte("hello world")

	keyPem, pubPem, err := GenerateKeyPair(2048)

	if err != nil {
		t.Error(err)
	}

	ef := EncryptedFile{
		plainText:  data,
		PublicPem:  pubPem,
		privatePem: keyPem,
	}

	err = ef.ParsePublicPem()
	if err != nil {
		t.Error(err)
	}

	err = ef.ParsePrivatePem()
	if err != nil {
		t.Error(err)
	}

	err = ef.GenerateSymmetricKey()
	if err != nil {
		t.Error(err)
	}

	err = ef.EncryptFile()
	if err != nil {
		t.Error(err)
	}

	if len(ef.ciphertext) == 0 {
		t.Error("ciphertext is empty")
	}

	if len(ef.nonce) == 0 {
		t.Error("nonce is empty")
	}

	if bytes.Equal(ef.plainText, ef.ciphertext) {
		t.Error("ciphertext and plaintext are the same")
	}

	dc := EncryptedFile{
		ciphertext: ef.ciphertext,
		privatePem: keyPem,
	}

	err = dc.ParsePrivatePem()
	if err != nil {
		t.Error(err)
	}

	err = dc.unpackFileAndDecrypt(ef.packFile())
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(ef.plainText, dc.plainText) {
		t.Error("plaintext and plaintext are different")
	}

}
