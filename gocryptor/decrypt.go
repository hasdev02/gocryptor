package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
)

func DecryptFile(file, password string) error {

	//OPEN FILE
	in, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("UNABLE TO OPEN THE FILE, ERROR: %w", err)
	}
	defer in.Close()

	//GET METADATA FROM ENCRYPTED FILE, METADATA IS ENCRYPTED SALT + NONCE
	encryptedMetadata := make([]byte, SaltSize + NonceSize)
	if _, err := in.Read(encryptedMetadata); err != nil {
		return fmt.Errorf("ERROR WHILE READING ENCRYPTED METADATA: %w", err)
	}

	//GET SALT FROM ENCRYPTED FILE
	salt := make([]byte, SaltSize)
	if _, err := in.Read(salt); err != nil {
		return fmt.Errorf("ERROR WHILE READING SALT: %w", err)
	}

	//GET NONCE FROM ENCRYPTED FILE
	nonce := make([]byte, NonceSize)
	if _, err := in.Read(nonce); err != nil {
		return fmt.Errorf("ERROR WHILE READING NONCE: %w", err)
	}

	//GET PASSWORD HASH, THIS IS THE ENCRYPTION KEY
	key := argon2.IDKey([]byte(password), salt, 1, ArgonMemory, 4, chacha20.KeySize)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return fmt.Errorf("ERROR WHILE INITILIAZE XCHACHA20 STREAM CIPHER: %w", err)
	}

	//VERIFY ENCRYPTED METADATA IS VALID
	expectedMetadata := make([]byte, SaltSize + NonceSize)
	cipher.XORKeyStream(expectedMetadata, append(salt, nonce...))

	if !bytes.Equal(expectedMetadata, encryptedMetadata) {
		return fmt.Errorf("INVALID METADATA, PASSWORD IS WRONG")
	}

	//CREATE DECRYPTED FILE
	out, err := os.Create(strings.TrimSuffix(file, EncryptedFileExtension) + "")
	if err != nil {
		return fmt.Errorf("UNABLE TO CREATE DECRYPTED FILE, ERROR: %w", err)
	}
	defer out.Close()

	//GET ENCRYPTED DATA SIZE
	encryptedFileStat, err := in.Stat()
	if err != nil {
		return fmt.Errorf("ERROR WHILE READING ENCRYPTED FILE STAT: %v", err)
	}

	//FULL FILE SIZE - (ENCRYPTED_METADATA) - (SALT) - (NONCE) - (SHA256SUM)
	encryptedDataSize := encryptedFileStat.Size() - MetadataSize - SaltSize - NonceSize - Sha256SumSize

	buffer := make([]byte, BlockSize)
	hasher := sha256.New()

	var readedBytes int64

	//DECRYPT LOOP, READ ENCRYPTED DATA IN BLOCKS OF 64KB
	for readedBytes < encryptedDataSize {

		remainingBytes := encryptedDataSize - readedBytes
		bytesToRead := int64(BlockSize)

		//Check if remaining bytes are less than block bytes, so we dont read the sha256sum
		if remainingBytes < bytesToRead {
			bytesToRead = remainingBytes
		}

		readBytes, err := in.Read(buffer[:bytesToRead])
		if err != nil {
			return fmt.Errorf("ERROR WHILE READING ENCRYPTED FILE: %w", err)
		}

		decryptedBuffer := make([]byte, readBytes)
		cipher.XORKeyStream(decryptedBuffer, buffer[:bytesToRead])

		if _, err := out.Write(decryptedBuffer); err != nil {
			return fmt.Errorf("ERROR WHILE WRITING DECRYPTED DATA: %w", err)
		}

		hasher.Write(decryptedBuffer)
		readedBytes += int64(readBytes)
	}

	sha256Sum := hasher.Sum(nil)

	//READ SHA256SUM FROM THE END OF THE FILE
	expectedSha256Sum := make([]byte, Sha256SumSize)
	_, err = in.Seek(-Sha256SumSize, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("ERROR WHILE SEARCHING SHA256SUM: %w", err)
	}
	_, err = in.Read(expectedSha256Sum)
	if err != nil {
		return fmt.Errorf("ERROR WHILE READING SHA256SUM: %w", err)
	}

	//CHECK IF BOTH SUMS ARE EQUAL
	if !bytes.Equal(sha256Sum, expectedSha256Sum) {
		return fmt.Errorf("SHA256 CHECK FAILED, FILE IS CORRUPTED")
	}

	return nil
}