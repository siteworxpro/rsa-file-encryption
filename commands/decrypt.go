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

	p.LogInfo("Reading and decrypting file...")
	c := make(chan bool)
	go p.LogSpinner("Decrypting...", c)

	err = encryptedFile.OsReadCipherTextFile(filePath)
	if err != nil {
		return err
	}

	c <- true

	p.LogInfo("Writing un-encrypted file...")
	err = encryptedFile.WriteDecryptedFileToDisk(outFile)
	if err != nil {
		return err
	}

	p.LogSuccess("Done!")

	return nil
}
