# GOCRYPTOR
Encrypt and decrypt files using XChaCha20

## USAGE

### ENCRYPT
`./gocryptor -mode=encrypt -file=file_path.txt -password=your_password`
### DECRYPT
`./gocryptor -mode=decrypt -file=encrypted_file_path.txt -password=your_password`

## METHOD
File is encrypted using XChaCha20 from a derived Argon2id key.
The first 16 bytes of the encrypted file contains HMAC_SHA256 calculated from the salt and nonce using the cipher key, followed by plaintext salt and nonce, then the encrypted file data. Sha256 sum of the original file is stored at the end.

With the HMAC_SHA256 we auth the decryption ensuring the password given is correct and also ensures the salt and nonce are valid.

With the sha256 hash we can detect any modification/corruption of the encrypted file.

File structure:
```
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
```

## PERFORMANCE:

3GB FILE: 16 seconds
```
$ time ./gocryptor.exe -mode=encrypt -file=kali-linux-2024.3-vmware-amd64.7z -password=mypassword
File encrypted successfully.

real    0m16.256s
user    0m0.000s
sys     0m0.015s

$ time ./gocryptor.exe -mode=decrypt -file=kali-linux-2024.3-vmware-amd64.7z.gocrypted -password=mypassword
File decrypted successfully.

real    0m15.027s
user    0m0.000s
sys     0m0.031s
```

3MB FILE: 
```
$ time ./gocryptor.exe -mode=encrypt -file=image.JPG -password=mypassword
File encrypted successfully.

real    0m0.255s
user    0m0.015s
sys     0m0.031s

$ time ./gocryptor.exe -mode=decrypt -file=image.JPG.gocrypted -password=mypassword
File decrypted successfully.

real    0m0.111s
user    0m0.000s
sys     0m0.015s
```



