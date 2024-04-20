package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"fmt"
	"os"
)

type EncryptedFile struct {
	ciphertext      []byte
	plainText       []byte
	nonce           []byte
	privatePem      []byte
	PublicPem       []byte
	privateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	symmetricKey    []byte
	symmetricKeyEnc []byte
}

func (f *EncryptedFile) packFile() []byte {
	file := append(f.nonce, f.ciphertext...)
	return append(file, f.symmetricKeyEnc...)
}

func (f *EncryptedFile) EncryptFile() error {
	c, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}

	f.nonce = make([]byte, aes.BlockSize)
	_, err = rand.Read(f.nonce)
	if err != nil {
		return err
	}

	cbc := cipher.NewCBCEncrypter(c, f.nonce)
	ciphertext := make([]byte, len(f.plainText))
	ciphertext = pad(ciphertext, aes.BlockSize)
	plaintextP := pad(f.plainText, aes.BlockSize)

	cbc.CryptBlocks(ciphertext, plaintextP)
	f.ciphertext = ciphertext

	return nil
}

func (f *EncryptedFile) OsReadPlainTextFile(path string) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.plainText = plaintext

	return nil
}

func (f *EncryptedFile) WriteEncryptFileToDisk(filePath string) error {
	packed := f.packFile()

	err := os.WriteFile(filePath+".enc", packed, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (f *EncryptedFile) WriteDecryptedFileToDisk(filePath string) error {
	err := os.WriteFile(filePath, f.plainText, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (f *EncryptedFile) unpackFileAndDecrypt(packedFile []byte) error {
	keyLen := f.privateKey.Size()

	lenWithoutKey := len(packedFile) - keyLen

	packedFile, f.symmetricKeyEnc = packedFile[0:lenWithoutKey], packedFile[lenWithoutKey:]

	err := f.decryptSymmetricKey()
	if err != nil {
		return err
	}

	a, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	f.nonce, f.ciphertext = packedFile[0:aes.BlockSize], packedFile[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(a, f.nonce)

	plainText := make([]byte, len(f.ciphertext))

	cbc.CryptBlocks(plainText, f.ciphertext)

	f.plainText, err = unPad(plainText)
	if err != nil {
		return err
	}

	return nil
}

func (f *EncryptedFile) OsReadCipherTextFile(path string) error {
	packedFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = f.unpackFileAndDecrypt(packedFile)
	if err != nil {
		return err
	}

	return nil
}

func pad(buf []byte, size int) []byte {
	if size < 1 || size > 255 {
		panic(fmt.Sprintf("pkcs7pad: inappropriate block size %d", size))
	}
	i := size - (len(buf) % size)
	return append(buf, bytes.Repeat([]byte{byte(i)}, i)...)
}

func unPad(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("pkcs7pad: bad padding")
	}

	padLen := buf[len(buf)-1]
	toCheck := 255
	good := 1
	if toCheck > len(buf) {
		toCheck = len(buf)
	}
	for i := 0; i < toCheck; i++ {
		b := buf[len(buf)-1-i]

		outOfRange := subtle.ConstantTimeLessOrEq(int(padLen), i)
		equal := subtle.ConstantTimeByteEq(padLen, b)
		good &= subtle.ConstantTimeSelect(outOfRange, 1, equal)
	}

	good &= subtle.ConstantTimeLessOrEq(1, int(padLen))
	good &= subtle.ConstantTimeLessOrEq(int(padLen), len(buf))

	if good != 1 {
		return nil, fmt.Errorf("pkcs7pad: bad padding")
	}

	return buf[:len(buf)-int(padLen)], nil
}
