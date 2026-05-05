package commands

import (
	"fmt"
	"github.com/siteworxpro/rsa-file-encryption/crypt"
	"github.com/siteworxpro/rsa-file-encryption/printer"
	"os"
)

func GenerateKeypair(bitSize uint, path string, overwrite bool) error {

	if _, err := os.Stat(path); err == nil && !overwrite {
		return fmt.Errorf("key file already exists - use another filename or -force (-F) to overwrite")
	}

	p := printer.NewPrinter()
	done := make(chan bool)
	type keyResult struct {
		keyPem, pubPem []byte
		err            error
	}
	genErr := make(chan keyResult, 1)

	go func() {
		k, pub, err := crypt.GenerateKeyPair(int(bitSize))
		genErr <- keyResult{k, pub, err}
		done <- true
	}()

	p.LogSpinner("Generating RSA key...", done)

	result := <-genErr
	if result.err != nil {
		return result.err
	}
	keyPem, pubPem := result.keyPem, result.pubPem

	p.LogInfo("Writing private key...")
	err := os.WriteFile(path, keyPem, 0600)
	if err != nil {
		return err
	}

	p.LogInfo("Writing public key...")
	err = os.WriteFile(path+".pub", pubPem, 0644)
	if err != nil {
		return err
	}

	p.LogSuccess("Done!")

	return nil
}
