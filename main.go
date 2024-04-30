package main

import (
	"github.com/siteworxpro/rsa-file-encryption/commands"
	"github.com/siteworxpro/rsa-file-encryption/printer"
	"github.com/urfave/cli/v2"
	"os"
	"time"
)

func main() {
	p := printer.NewPrinter()
	p.PrintTitle()

	app := &cli.App{
		Name:                 "rsa-file-encryption",
		Version:              printer.Version,
		Compiled:             time.Now(),
		EnableBashCompletion: true,
		Usage:                "a file encryption tool using rsa key pairs to encrypt files using AES-256-CBC",
		Commands: []*cli.Command{
			{
				Name:    "encrypt",
				Aliases: []string{"e", "en"},
				Usage:   "encrypt a file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "file to encrypt",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "public-key",
						Aliases:  []string{"p"},
						Usage:    "public key path",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"F"},
						Usage:   "overwrite the encrypted file",
					},
				},
				Action: func(c *cli.Context) error {
					return commands.Encrypt(c.String("public-key"), c.String("file"), c.Bool("force"))
				},
			},
			{
				Name:    "decrypt",
				Aliases: []string{"d", "de"},
				Usage:   "decrypt a file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "file to decrypt",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "private-key",
						Aliases:  []string{"p"},
						Usage:    "private key path",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "out",
						Aliases:  []string{"o"},
						Usage:    "output file name",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"F"},
						Usage:   "overwrite the encrypted file",
					},
				},
				Action: func(c *cli.Context) error {
					return commands.Decrypt(c.String("private-key"), c.String("file"), c.String("out"), c.Bool("force"))
				},
			},
			{
				Name:    "generate-keypair",
				Aliases: []string{"g", "gk"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "size",
						Aliases:     []string{"s"},
						Usage:       "the size of the private key",
						DefaultText: "4096",
					},
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "the path to the private key file",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"F"},
						Usage:   "overwrite the private key file",
					},
				},
				Usage: "generate a keypair",
				Action: func(c *cli.Context) error {
					return commands.GenerateKeypair(c.Uint("size"), c.String("file"), c.Bool("force"))
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		p.LogError("error" + err.Error())

		os.Exit(1)
	}
}
