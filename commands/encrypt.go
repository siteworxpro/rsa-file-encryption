package commands

import (
	"fmt"
	"os"

	"github.com/siteworxpro/rsa-file-encryption/crypt"
	"github.com/siteworxpro/rsa-file-encryption/printer"
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

	if encryptedFile.PublicKey.Size() < 256 {
		return fmt.Errorf("key to weak. use stronger key > 2048 bits")
	}

	err = encryptedFile.GenerateSymmetricKey()
	if err != nil {
		return err
	}

	done := make(chan bool)
	encErr := make(chan error, 1)

	go func() {
		encErr <- encryptedFile.EncryptFilePath(filePath, filePath+".enc")
		done <- true
	}()

	p.LogSpinner("Encrypting...", done)

	if err = <-encErr; err != nil {
		return err
	}

	p.LogSuccess("Done!")
	return nil
}
