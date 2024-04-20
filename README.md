# RSA Public/Private Key File Encryption

## Build

Nothing special is needed to build.

```
go build --ldflags="-X 'github.com/siteworxpro/rsa-file-encryption/printer.Version=$(git describe --tags --abbrev=0)'"
```

## Generating Keys

Generates a set of RSA key pairs. Default size is 4096 bits. Minimum size is 1024 bits and maximum is 16384 bits

```
NAME:
rsa-file-encryption generate-keypair - generate a keypair

USAGE:
rsa-file-encryption generate-keypair [command options] [arguments...]

OPTIONS:
--size value, -s value  the size of the private key (default: 4096)
--file value, -f value  the path to the private key file
--force, -F             overwrite the private key file (default: false)
--help, -h              show help
```

```bash
./rsa-file-encryption generate-keypair -s 4096 -f my-key
```

## Encrypting

Encrypt a file with a public RSA Key

```
NAME:
   rsa-file-encryption encrypt - encrypt a file

USAGE:
   rsa-file-encryption encrypt [command options] [arguments...]

OPTIONS:
   --file value, -f value        file to encrypt
   --public-key value, -p value  public key path
   --force, -F                   overwrite the encrypted file (default: false)
   --help, -h                    show help
```

```bash
./rsa-file-encryption encrypt --file file_to_encrypt.txt --public-key my-key.pub
```

## Decrypting

Decrypt a file with a private RSA key

```
NAME:
   rsa-file-encryption decrypt - decrypt a file

USAGE:
   rsa-file-encryption decrypt [command options] [arguments...]

OPTIONS:
   --file value, -f value         file to decrypt
   --private-key value, -p value  private key path
   --out value, -o value          output file name
   --force, -F                    overwrite the encrypted file (default: false)
   --help, -h                     show help
```

```bash
./rsa-file-encryption decrypt --file file_to_encrypt.txt.enc --out file_decrypted --private-key my-key
```