# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build (dev)
go build

# Build with version tag
go build --ldflags="-X 'github.com/siteworxpro/rsa-file-encryption/printer.Version=$(git describe --tags --abbrev=0)'"

# Run tests
go test -v ./...

# Run single package tests
go test -v ./crypt/...

# Cross-platform release build (linux + darwin, GPG signs each binary)
./build.sh
```

## Architecture

Hybrid encryption: RSA wraps an AES-256 session key; the file is encrypted with AES-256-CBC + PKCS7 padding + HMAC-SHA256 integrity check.

**`crypt/` package** — all crypto logic, no I/O to stdout.
- `EncryptedFile` struct holds all state (keys, nonce, ciphertext, hmac, plaintext).
- `file.go` — encrypt/decrypt pipeline + binary pack format: `[nonce(16)] [ciphertext] [RSA-encrypted-symmetric-key] ["::HMAC::"] [hmac(32)]`
- `keys.go` — RSA key generation, PEM parsing (supports both PKCS1 and PKCS8/PKIX), AES symmetric key generation and RSA-OAEP-SHA512 wrap/unwrap.
- `pem.go` — `GenerateKeyPair(size uint)` writes PKCS1 PEM; valid range 2048–16384 (0 = default 4096).

**`commands/`** — thin CLI handlers; call `crypt` methods and write results to disk.

**`printer/`** — Bubble Tea / Lipgloss terminal UI; `Version` var injected at build time via ldflags.

**`main.go`** — `urfave/cli/v2` wiring for three subcommands: `encrypt`, `decrypt`, `generate-keypair`.

## Encrypted file format

Files are packed as a single binary blob. During decrypt, `unpackFileAndDecrypt` splits by the literal sentinel `::HMAC::` to separate the HMAC, then strips the last `privateKey.Size()` bytes as the encrypted symmetric key, and treats the remainder as `[nonce][ciphertext]`. Files without an HMAC suffix are still accepted (backwards compatibility).

## Repository

Hosted on `gitea.siteworxpro.com` — use Gitea MCP tools, not `gh`.
