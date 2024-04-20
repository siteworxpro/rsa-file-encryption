package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func (f *EncryptedFile) encryptSymmetricKey() error {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, f.PublicKey, f.symmetricKey, nil)
	if err != nil {
		return err
	}

	f.symmetricKeyEnc = ciphertext

	return nil
}

func (f *EncryptedFile) decryptSymmetricKey() error {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, f.privateKey, f.symmetricKeyEnc, nil)
	if err != nil {
		return err
	}

	f.symmetricKey = plaintext

	return nil
}

func (f *EncryptedFile) OsReadPublicKey(path string) error {
	pemKey, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	f.PublicPem = pemKey
	err = f.ParsePublicPem()
	if err != nil {
		return err
	}

	return nil
}

func (f *EncryptedFile) OsReadPrivateKey(path string) error {
	pemKey, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	f.privatePem = pemKey

	err = f.ParsePrivatePem()
	if err != nil {
		return err
	}

	return nil
}

func (f *EncryptedFile) GenerateSymmetricKey() error {
	symKey := make([]byte, 32)
	_, err := rand.Read(symKey)
	if err != nil {
		return err
	}

	f.symmetricKey = symKey

	err = f.encryptSymmetricKey()
	if err != nil {
		return err
	}

	return nil
}

func (f *EncryptedFile) ParsePublicPem() error {
	pemKeyBin, _ := pem.Decode(f.PublicPem)

	if bytes.Contains(f.PublicPem, []byte("-----BEGIN PUBLIC KEY-----")) {
		key, err := x509.ParsePKIXPublicKey(pemKeyBin.Bytes)
		if err != nil {
			return err
		}

		f.PublicKey = key.(*rsa.PublicKey)
		return nil
	}

	pubKey, err := x509.ParsePKCS1PublicKey(pemKeyBin.Bytes)

	if err != nil {
		return err
	}

	f.PublicKey = pubKey

	return nil
}

func (f *EncryptedFile) ParsePrivatePem() error {
	pemKeyBin, _ := pem.Decode(f.privatePem)

	if bytes.Contains(f.privatePem, []byte("-----BEGIN PRIVATE KEY-----")) {
		key, err := x509.ParsePKCS8PrivateKey(pemKeyBin.Bytes)
		if err != nil {
			return err
		}

		f.privateKey = key.(*rsa.PrivateKey)
		return nil
	}

	privKey, err := x509.ParsePKCS1PrivateKey(pemKeyBin.Bytes)
	if err != nil {
		return err
	}

	f.privateKey = privKey

	return nil
}
