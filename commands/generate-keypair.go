package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/siteworxpro/rsa-file-encryption/printer"
	"os"
)

func GenerateKeypair(bitSize uint, path string, overwrite bool) error {
	if bitSize == 0 {
		bitSize = 4096
	}

	if bitSize < 2048 {
		return fmt.Errorf("key to weak. size must be greater than 2048")
	}

	if bitSize > 16384 {
		return fmt.Errorf("key to large. size must be less than 16384")
	}

	if _, err := os.Stat(path); err == nil && !overwrite {
		return fmt.Errorf("key file already exists - use another filename or -force (-F) to overwrite")
	}

	p := printer.NewPrinter()
	c := make(chan bool)

	go p.LogSpinner("Generating RSA key...", c)
	key, err := rsa.GenerateKey(rand.Reader, int(bitSize))
	c <- true

	if err != nil {
		return err
	}

	pub := key.Public()

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	p.LogInfo("Writing private key...")
	err = os.WriteFile(path, keyPEM, 0600)
	if err != nil {
		return err
	}

	p.LogInfo("Writing public key...")
	err = os.WriteFile(path+".pub", pubPEM, 0644)
	if err != nil {
		return err
	}

	p.LogSuccess("Done!")
	return nil
}
