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
	c := make(chan bool)

	go p.LogSpinner("Generating RSA key...", c)

	keyPem, pubPem, err := crypt.GenerateKeyPair(int(bitSize))

	c <- true

	p.LogInfo("Writing private key...")
	err = os.WriteFile(path, keyPem, 0600)
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
