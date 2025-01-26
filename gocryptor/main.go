package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	Sha256SumSize = 32
	SaltSize = 16
	NonceSize = 24
	BlockSize = 64 * 1024
	EncryptedFileExtension = ".gocrypted"
	ArgonIterations = 3
	ArgonMemory = 64 * 1024 //64 MB
	HmacSize = 32
)

/*
ENCRYPTED FILE STRUCTURE

+--------------------------+---------------------------------------+
|        HMAC              |      HMAC-SHA256                      |
|      (32bytes)           |                                       |
+--------------------------+---------------------------------------+
|       Salt  (16 bytes)   |  ARGON2 HASH SALT                     |
+--------------------------+---------------------------------------+
|       Nonce   (24 bytes) |  XCHACHA20 NONCE                      |
+--------------------------+---------------------------------------+
|       ENCRYPTED FILE     |  ENCRYPTED WITH XCHACHA20             |
|       (variable)         |                                       |
+--------------------------+---------------------------------------+
|       SHA256 HASH        |  DECRYPTED FILE HASH                  |
|       (32 bytes)         |                                       |
+--------------------------+---------------------------------------+ 
*/

func main() {
	// PARAMETERS
	mode := flag.String("mode", "", "Mode: encrypt or decrypt")
	file := flag.String("file", "", "File path")
	password := flag.String("password", "", "Password for encryption/decryption")

	flag.Parse()

	// CHECK NON EMPTY PARAMETERS
	if *mode == "" || *file == "" || *password == "" {
		fmt.Println("PARAMETERS: -mode=(encrypt|decrypt) -file=<file_path> -password=<password>")
		os.Exit(1)
	}

	if *mode == "encrypt" || *mode == "e" {
		if err := EncryptFile(*file, *password); err != nil {
			fmt.Printf("Error during encryption: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("File encrypted successfully.")
	} else if *mode == "decrypt" || *mode == "d" {
		if err := DecryptFile(*file, *password); err != nil {
			fmt.Printf("Error during decryption: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("File decrypted successfully.")
	} else {
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'.")
		os.Exit(1)
	}
}