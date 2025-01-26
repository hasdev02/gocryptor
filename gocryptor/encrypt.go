package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
)

func EncryptFile(file, password string) error {

	//OPEN FILE
	in, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("UNABLE TO OPEN THE FILE, ERROR: %w", err)
	}
	defer in.Close()

	//CREATE OUTPUT FILE
	out, err := os.Create(file + EncryptedFileExtension)
	if err != nil {
		return fmt.Errorf("UNABLE TO CREATE ENCRYPTED FILE: %w", err)
	}
	defer out.Close()

	//GENERATE 16 BYTES SALT
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("ERROR WHILE GENERATING SALT: %w", err)
		
	}

	//KEY IS PASSWORD ARGON2 HASH
	key := argon2.IDKey([]byte(password), salt, ArgonIterations, ArgonMemory, 4, chacha20.KeySize)

	//GENERATE NONCE
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("ERROR WHILE GENERATING NONCE: %w", err)
	}

	//CREATE XCHACHA20 CIPHER STREAM
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return fmt.Errorf("ERROR WHILE INITILIAZE XCHACHA20 AEAD: %w", err)
	}

	//GENERATE HMAC
	hmac := hmac.New(sha256.New, key)
	hmac.Write(append(salt, nonce...))
	hmacData := hmac.Sum(nil)

	//WRITE HMAC AT THE START OF THE FILE
	if _, err := out.Write(hmacData); err != nil {
		return fmt.Errorf("ERROR WHILE WRITING HMAC AT THE START OF THE FILE: %w", err)
	}

	//WRITE HASH SALT AND NONCE AT THE START OF THE FILE
	if _, err := out.Write(salt); err != nil {
		return fmt.Errorf("ERROR WHILE WRITING SALT AT THE START OF THE FILE: %w", err)
	}
	if _, err := out.Write(nonce); err != nil {
		return fmt.Errorf("ERROR WHILE WRITING NONCE AT THE START OF THE FILE: %w", err)
	}

	buffer := make([]byte, BlockSize)
	hasher := sha256.New()

	//CIPHER LOOP, WE READ WHOLE FILE IN BLOCKS OF 64KB
	for {
		readBytes, err := in.Read(buffer)

		//If we read data
		if readBytes > 0 {
			cipherbuffer := make([]byte, readBytes)
			cipher.XORKeyStream(cipherbuffer, buffer[:readBytes])
			if _, err := out.Write(cipherbuffer); err != nil {
				return fmt.Errorf("ERROR WHILE WRITING CIPHER DATA: %w", err)
			}

			hasher.Write(buffer[:readBytes])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ERROR WHILE READING ENCRYPTED FILE: %w", err)
		}
	}

	//WRITE SHA256 SUM AT FILE END
	sha256Sum := hasher.Sum(nil)
	if _, err := out.Write(sha256Sum); err != nil {
		return fmt.Errorf("ERROR WHILE WRITING SHA256 SUM: %w", err)
	}

	return nil
}