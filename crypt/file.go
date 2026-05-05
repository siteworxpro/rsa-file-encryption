package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// hmacKey is the sentinel delimiter used in the legacy V1 file format.
const hmacKey = "::HMAC::"

// fileMagic marks V2 (AES-GCM, in-memory) encrypted files.
const fileMagic = "RSE\x01"

// fileMagicV3 marks V3 (AES-GCM, streaming) encrypted files.
const fileMagicV3 = "RSE\x02"

// gcmNonceSize is the standard AES-GCM nonce length.
const gcmNonceSize = 12

// chunkSize is the plaintext chunk size used in V3 streaming encryption.
const chunkSize = 1 << 20 // 1MB

type EncryptedFile struct {
	ciphertext      []byte
	hmac            []byte
	plainText       []byte
	nonce           []byte
	privatePem      []byte
	PublicPem       []byte
	privateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	symmetricKey    []byte
	symmetricKeyEnc []byte
}

// packFile returns a V2 packed file:
// [magic(4)][nonce(12)][ciphertext+gcm_tag][enc_key]
func (f *EncryptedFile) packFile() []byte {
	out := make([]byte, 0, len(fileMagic)+len(f.nonce)+len(f.ciphertext)+len(f.symmetricKeyEnc))
	out = append(out, []byte(fileMagic)...)
	out = append(out, f.nonce...)
	out = append(out, f.ciphertext...)
	out = append(out, f.symmetricKeyEnc...)
	return out
}

// packFileLegacy returns a V1 (CBC+HMAC) packed file. Used only in tests.
func (f *EncryptedFile) packFileLegacy() []byte {
	file := append(f.nonce, f.ciphertext...)
	file = append(file, f.symmetricKeyEnc...)
	if len(f.hmac) > 0 {
		file = append(file, []byte(hmacKey)...)
		file = append(file, f.hmac...)
	}
	return file
}

// EncryptFile encrypts plainText with AES-256-GCM into memory (V2 format).
// For large files prefer EncryptFilePath.
func (f *EncryptedFile) EncryptFile() error {
	block, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	f.nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(f.nonce); err != nil {
		return err
	}
	f.ciphertext = gcm.Seal(nil, f.nonce, f.plainText, nil)
	return nil
}

// encryptFileLegacy encrypts with AES-256-CBC + HMAC-SHA256 (V1 format). Used only in tests.
func (f *EncryptedFile) encryptFileLegacy() error {
	c, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	f.nonce = make([]byte, aes.BlockSize)
	if _, err = rand.Read(f.nonce); err != nil {
		return err
	}
	cbc := cipher.NewCBCEncrypter(c, f.nonce)
	plaintextP := pad(f.plainText, aes.BlockSize)
	ciphertext := make([]byte, len(plaintextP))
	cbc.CryptBlocks(ciphertext, plaintextP)
	f.ciphertext = ciphertext

	mac := hmac.New(sha256.New, f.symmetricKey)
	mac.Write(f.nonce)
	mac.Write(f.ciphertext)
	f.hmac = mac.Sum(nil)
	return nil
}

// EncryptFilePath streams inPath through AES-256-GCM in 1MB chunks and writes
// V3 format to outPath. Peak memory is O(chunk size), not O(file size).
func (f *EncryptedFile) EncryptFilePath(inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	block, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// 4-byte random prefix; chunk nonce = prefix(4) || uint64(chunkIndex)(8)
	noncePrefix := make([]byte, 4)
	if _, err = rand.Read(noncePrefix); err != nil {
		return err
	}

	// V3 header: [magic(4)][enc_key(keyLen)][nonce_prefix(4)]
	for _, b := range [][]byte{[]byte(fileMagicV3), f.symmetricKeyEnc, noncePrefix} {
		if _, err = out.Write(b); err != nil {
			return err
		}
	}

	buf := make([]byte, chunkSize)
	lenBuf := make([]byte, 4)
	var chunkIdx uint64

	for {
		n, readErr := io.ReadFull(in, buf)
		if n > 0 {
			nonce := make([]byte, gcmNonceSize)
			copy(nonce[:4], noncePrefix)
			binary.BigEndian.PutUint64(nonce[4:], chunkIdx)

			ct := gcm.Seal(nil, nonce, buf[:n], nil)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ct)))
			if _, err = out.Write(lenBuf); err != nil {
				return err
			}
			if _, err = out.Write(ct); err != nil {
				return err
			}
			chunkIdx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

// DecryptFilePath decrypts inPath to outPath. V3 files are streamed (O(chunk) memory);
// V1/V2 files fall back to in-memory decryption for backwards compatibility.
func (f *EncryptedFile) DecryptFilePath(inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err = io.ReadFull(in, header); err != nil {
		in.Close()
		return fmt.Errorf("failed to read file header: %w", err)
	}

	if string(header) == fileMagicV3 {
		// in is positioned just after the magic; decryptStreamV3 reads the rest
		defer in.Close()
		return f.decryptStreamV3(in, outPath)
	}

	// V1 or V2: load full file into memory
	in.Close()
	if err = f.OsReadCipherTextFile(inPath); err != nil {
		return err
	}
	return f.WriteDecryptedFileToDisk(outPath)
}

func (f *EncryptedFile) decryptStreamV3(r io.Reader, outPath string) error {
	keyLen := f.privateKey.Size()

	// Read enc_key and nonce_prefix (magic already consumed by caller)
	f.symmetricKeyEnc = make([]byte, keyLen)
	if _, err := io.ReadFull(r, f.symmetricKeyEnc); err != nil {
		return fmt.Errorf("failed to read encrypted key: %w", err)
	}
	if err := f.decryptSymmetricKey(); err != nil {
		return err
	}

	noncePrefix := make([]byte, 4)
	if _, err := io.ReadFull(r, noncePrefix); err != nil {
		return fmt.Errorf("failed to read nonce prefix: %w", err)
	}

	block, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	lenBuf := make([]byte, 4)
	var chunkIdx uint64

	for {
		_, readErr := io.ReadFull(r, lenBuf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("failed to read chunk length: %w", readErr)
		}

		ct := make([]byte, binary.BigEndian.Uint32(lenBuf))
		if _, err = io.ReadFull(r, ct); err != nil {
			return fmt.Errorf("failed to read chunk %d: %w", chunkIdx, err)
		}

		nonce := make([]byte, gcmNonceSize)
		copy(nonce[:4], noncePrefix)
		binary.BigEndian.PutUint64(nonce[4:], chunkIdx)

		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("decryption failed at chunk %d: %w", chunkIdx, err)
		}
		if _, err = out.Write(pt); err != nil {
			return err
		}
		chunkIdx++
	}
	return nil
}

func (f *EncryptedFile) OsReadPlainTextFile(path string) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.plainText = plaintext
	return nil
}

func (f *EncryptedFile) WriteEncryptFileToDisk(filePath string) error {
	return os.WriteFile(filePath+".enc", f.packFile(), 0600)
}

func (f *EncryptedFile) WriteDecryptedFileToDisk(filePath string) error {
	return os.WriteFile(filePath, f.plainText, 0600)
}

func (f *EncryptedFile) unpackFileAndDecrypt(packedFile []byte) error {
	if len(packedFile) >= len(fileMagic) && string(packedFile[:len(fileMagic)]) == fileMagic {
		return f.unpackFileAndDecryptV2(packedFile)
	}
	return f.unpackFileAndDecryptV1(packedFile)
}

func (f *EncryptedFile) unpackFileAndDecryptV2(packedFile []byte) error {
	keyLen := f.privateKey.Size()
	data := packedFile[len(fileMagic):]
	if len(data) < gcmNonceSize+16+keyLen {
		return fmt.Errorf("packed file is too short to be valid")
	}

	encKeyStart := len(data) - keyLen
	f.nonce = data[:gcmNonceSize]
	f.ciphertext = data[gcmNonceSize:encKeyStart]
	f.symmetricKeyEnc = data[encKeyStart:]

	if err := f.decryptSymmetricKey(); err != nil {
		return err
	}

	block, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plaintext, err := gcm.Open(nil, f.nonce, f.ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	f.plainText = plaintext
	return nil
}

// unpackFileAndDecryptV1 decrypts legacy CBC+HMAC files.
func (f *EncryptedFile) unpackFileAndDecryptV1(packedFile []byte) error {
	keyLen := f.privateKey.Size()
	if len(packedFile) < aes.BlockSize+keyLen {
		return fmt.Errorf("packed file is too short to be valid")
	}

	var storedHmac []byte
	if bytes.Contains(packedFile, []byte(hmacKey)) {
		parts := bytes.SplitN(packedFile, []byte(hmacKey), 2)
		packedFile, storedHmac = parts[0], parts[1]
	}

	lenWithoutKey := len(packedFile) - keyLen
	if lenWithoutKey < aes.BlockSize {
		return fmt.Errorf("packed file is too short to contain valid nonce and ciphertext")
	}

	f.symmetricKeyEnc = packedFile[lenWithoutKey:]
	if err := f.decryptSymmetricKey(); err != nil {
		return err
	}

	// nonce and ciphertext must be set before HMAC verification
	f.nonce = packedFile[0:aes.BlockSize]
	f.ciphertext = packedFile[aes.BlockSize:lenWithoutKey]

	if len(storedHmac) > 0 {
		mac := hmac.New(sha256.New, f.symmetricKey)
		mac.Write(f.nonce)
		mac.Write(f.ciphertext)
		if !hmac.Equal(mac.Sum(nil), storedHmac) {
			return fmt.Errorf("hmac verification failed")
		}
	}

	a, err := aes.NewCipher(f.symmetricKey)
	if err != nil {
		return err
	}
	cbc := cipher.NewCBCDecrypter(a, f.nonce)
	plainText := make([]byte, len(f.ciphertext))
	cbc.CryptBlocks(plainText, f.ciphertext)

	f.plainText, err = unPad(plainText)
	return err
}

func (f *EncryptedFile) OsReadCipherTextFile(path string) error {
	packedFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return f.unpackFileAndDecrypt(packedFile)
}

func pad(buf []byte, size int) []byte {
	if size < 1 || size > 255 {
		panic(fmt.Sprintf("pkcs7pad: inappropriate block size %d", size))
	}
	i := size - (len(buf) % size)
	return append(buf, bytes.Repeat([]byte{byte(i)}, i)...)
}

func unPad(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("pkcs7pad: bad padding")
	}

	padLen := buf[len(buf)-1]
	toCheck := 255
	good := 1
	if toCheck > len(buf) {
		toCheck = len(buf)
	}
	for i := 0; i < toCheck; i++ {
		b := buf[len(buf)-1-i]

		outOfRange := subtle.ConstantTimeLessOrEq(int(padLen), i)
		equal := subtle.ConstantTimeByteEq(padLen, b)
		good &= subtle.ConstantTimeSelect(outOfRange, 1, equal)
	}

	good &= subtle.ConstantTimeLessOrEq(1, int(padLen))
	good &= subtle.ConstantTimeLessOrEq(int(padLen), len(buf))

	if good != 1 {
		return nil, fmt.Errorf("pkcs7pad: bad padding")
	}

	return buf[:len(buf)-int(padLen)], nil
}
