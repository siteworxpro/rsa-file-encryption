package commands

import (
	"fmt"
	"github.com/siteworxpro/rsa-file-encryption/crypt"
	"github.com/siteworxpro/rsa-file-encryption/printer"
	"os"
)

func Decrypt(privateKeyPath string, filePath string, outFile string, force bool) error {

	if _, err := os.Stat(privateKeyPath); err != nil {
		return err
	}

	if _, err := os.Stat(filePath); err != nil {
		return err
	}

	if _, err := os.Stat(outFile); err == nil && !force {
		return fmt.Errorf("decrypted file already exists (--force, -F) to overwrite")
	}

	p := printer.NewPrinter()
	encryptedFile := crypt.EncryptedFile{}

	p.LogInfo("Reading Private Key...")
	err := encryptedFile.OsReadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}

	done := make(chan bool)
	decErr := make(chan error, 1)

	go func() {
		decErr <- encryptedFile.DecryptFilePath(filePath, outFile)
		done <- true
	}()

	p.LogSpinner("Decrypting...", done)

	if err = <-decErr; err != nil {
		return err
	}

	p.LogSuccess("Done!")
	return nil
}
