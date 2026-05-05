package crypt

import (
	"bytes"
	"os"
	"testing"
)

func TestLimitsKeySize(t *testing.T) {
	_, _, err := GenerateKeyPair(512)
	if err == nil {
		t.Errorf("GenerateKeyPair returned no error")
	}

	_, _, err = GenerateKeyPair(16385)
	if err == nil {
		t.Errorf("GenerateKeyPair returned no error")
	}

	_, _, err = GenerateKeyPair(0)
	if err != nil {
		t.Errorf("GenerateKeyPair returned an error")
	}
}

func TestEncryption(t *testing.T) {
	data := []byte("hello world")

	keyPem, pubPem, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	ef := EncryptedFile{
		plainText:  data,
		PublicPem:  pubPem,
		privatePem: keyPem,
	}

	if err = ef.ParsePublicPem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.GenerateSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err = ef.EncryptFile(); err != nil {
		t.Fatal(err)
	}

	if len(ef.ciphertext) == 0 {
		t.Error("ciphertext is empty")
	}
	if len(ef.nonce) != gcmNonceSize {
		t.Errorf("nonce length: got %d, want %d", len(ef.nonce), gcmNonceSize)
	}
	if bytes.Equal(ef.plainText, ef.ciphertext) {
		t.Error("ciphertext and plaintext are the same")
	}

	packed := ef.packFile()
	if string(packed[:len(fileMagic)]) != fileMagic {
		t.Error("packed file missing V2 magic header")
	}

	dc := EncryptedFile{privatePem: keyPem}
	if err = dc.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = dc.unpackFileAndDecrypt(packed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ef.plainText, dc.plainText) {
		t.Error("decrypted plaintext does not match original")
	}
}

func TestLegacyDecryption(t *testing.T) {
	data := []byte("hello world legacy")

	keyPem, pubPem, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	ef := EncryptedFile{
		plainText:  data,
		PublicPem:  pubPem,
		privatePem: keyPem,
	}

	if err = ef.ParsePublicPem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.GenerateSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err = ef.encryptFileLegacy(); err != nil {
		t.Fatal(err)
	}

	packed := ef.packFileLegacy()

	dc := EncryptedFile{privatePem: keyPem}
	if err = dc.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = dc.unpackFileAndDecrypt(packed); err != nil {
		t.Fatalf("legacy decrypt failed: %v", err)
	}
	if !bytes.Equal(ef.plainText, dc.plainText) {
		t.Error("decrypted plaintext does not match original")
	}
}

func TestStreamEncryptDecrypt(t *testing.T) {
	data := []byte("streaming hello world — chunk me up")

	keyPem, pubPem, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	encFile := EncryptedFile{PublicPem: pubPem, privatePem: keyPem}
	if err = encFile.ParsePublicPem(); err != nil {
		t.Fatal(err)
	}
	if err = encFile.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = encFile.GenerateSymmetricKey(); err != nil {
		t.Fatal(err)
	}

	inFile, err := os.CreateTemp(t.TempDir(), "plaintext-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inFile.Write(data); err != nil {
		t.Fatal(err)
	}
	inFile.Close()

	encPath := inFile.Name() + ".enc"
	if err = encFile.EncryptFilePath(inFile.Name(), encPath); err != nil {
		t.Fatalf("EncryptFilePath: %v", err)
	}

	decFile := EncryptedFile{privatePem: keyPem}
	if err = decFile.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	outPath := inFile.Name() + ".dec"
	if err = decFile.DecryptFilePath(encPath, outPath); err != nil {
		t.Fatalf("DecryptFilePath: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, got) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, data)
	}
}

func TestStreamDecryptFallbackV2(t *testing.T) {
	data := []byte("v2 fallback test")

	keyPem, pubPem, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	ef := EncryptedFile{plainText: data, PublicPem: pubPem, privatePem: keyPem}
	if err = ef.ParsePublicPem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.GenerateSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err = ef.EncryptFile(); err != nil {
		t.Fatal(err)
	}

	// Write a V2 file to disk
	dir := t.TempDir()
	encPath := dir + "/test.enc"
	if err = os.WriteFile(encPath, ef.packFile(), 0600); err != nil {
		t.Fatal(err)
	}

	// DecryptFilePath should fall back to in-memory V2 path
	dc := EncryptedFile{privatePem: keyPem}
	if err = dc.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	outPath := dir + "/test.dec"
	if err = dc.DecryptFilePath(encPath, outPath); err != nil {
		t.Fatalf("DecryptFilePath V2 fallback: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, got) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, data)
	}
}

func TestLegacyDecryptionWithoutHmac(t *testing.T) {
	data := []byte("no hmac legacy file")

	keyPem, pubPem, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	ef := EncryptedFile{
		plainText:  data,
		PublicPem:  pubPem,
		privatePem: keyPem,
	}

	if err = ef.ParsePublicPem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = ef.GenerateSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err = ef.encryptFileLegacy(); err != nil {
		t.Fatal(err)
	}

	// simulate a pre-HMAC legacy file by packing without the HMAC field
	ef.hmac = nil
	packed := ef.packFileLegacy()

	dc := EncryptedFile{privatePem: keyPem}
	if err = dc.ParsePrivatePem(); err != nil {
		t.Fatal(err)
	}
	if err = dc.unpackFileAndDecrypt(packed); err != nil {
		t.Fatalf("legacy decrypt (no hmac) failed: %v", err)
	}
	if !bytes.Equal(ef.plainText, dc.plainText) {
		t.Error("decrypted plaintext does not match original")
	}
}
