package commands

import (
	"fmt"
	"github.com/siteworxpro/rsa-file-encryption/crypt"
	"github.com/siteworxpro/rsa-file-encryption/printer"
	"os"
)

func Encrypt(publicKeyPath string, filePath string, force bool) error {

	if _, err := os.Stat(publicKeyPath); err != nil {
		return err
	}

	if _, err := os.Stat(filePath); err != nil {
		return err
	}

	if _, err := os.Stat(filePath + ".enc"); err == nil && !force {
		return fmt.Errorf("encrypted file already exists (--force, -F) to overwrite")
	}

	p := printer.NewPrinter()
	encryptedFile := crypt.EncryptedFile{}

	p.LogInfo("Reading public key...")
	err := encryptedFile.OsReadPublicKey(publicKeyPath)
	if err != nil {
		return err
	}

	size := encryptedFile.PublicKey.Size()
	if size < 256 {
		return fmt.Errorf("key to weak. use stronger key > 2048 bits")
	}

	p.LogInfo("Reading file to encrypt...")
	err = encryptedFile.OsReadPlainTextFile(filePath)
	if err != nil {
		return err
	}

	c := make(chan bool)
	go p.LogSpinner("Encrypting...", c)

	err = encryptedFile.GenerateSymmetricKey()
	if err != nil {
		return err
	}

	err = encryptedFile.EncryptFile()
	if err != nil {
		return err
	}

	c <- true

	p.LogInfo("Encrypted file successfully")
	p.LogInfo("Writing file...")
	err = encryptedFile.WriteEncryptFileToDisk(filePath)
	if err != nil {
		return err
	}

	p.LogSuccess("Done!")
	return nil
}
