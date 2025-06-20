# Encryptator_Python3
Python3 script to use with [Encryptator](https://play.google.com/store/apps/details?id=lu.monks.banalapps.encryptator).

This script is provided for transparency purposes to the users who want to prove themselves that the application is secure to use.

It currently only supports text encryption. File encryption will be added soon.

***Any meaningful contribution to this side project is appreciated. You can reach out and create pull requests or forks to propose improvements.***

## How to use this script
```
docker run -it --rm ghcr.io/banalapps/encryptator_python3:latest
```

## Example encryption
```
docker run -it --rm ghcr.io/banalapps/encryptator_python3:latest
Choose encryption algorithm:
1. AES
2. ChaCha20
Enter the number of your choice: 1
Choose salt size:
1. 16 bytes
2. 32 bytes
3. 48 bytes
4. 64 bytes
Enter the number of your choice: 1
Choose KDF algorithm:
1. Argon2id
2. Scrypt
3. PBKDF2
Enter the number of your choice: 1
Choose time cost for Argon2id:
1. 2 iterations
2. 4 iterations
3. 6 iterations
4. 12 iterations
Enter the number of your choice: 1
Choose memory cost for Argon2id:
1. 19456 MiB
2. 28672 MiB
3. 37888 MiB
4. 75776 MiB
Enter the number of your choice: 1
Choose operation:
1. Encrypt
2. Decrypt
Enter the number of your choice: 1
Enter password: MySecurePassword!
Enter input data: This is a test string.
Encrypted Data:
Bb3DS8N79cJWDAS9IsjNaNRPiXfh2dhPSA6OqdDi1svaEtxp34TNS2HtOULmDmtE6bskMgfIRcubT8q6gSpaefzz
```

## Example decryption
```
docker run -it --rm ghcr.io/banalapps/encryptator_python3:latest
Choose encryption algorithm:
1. AES
2. ChaCha20
Enter the number of your choice: 1
Choose salt size:
1. 16 bytes
2. 32 bytes
3. 48 bytes
4. 64 bytes
Enter the number of your choice: 1
Choose KDF algorithm:
1. Argon2id
2. Scrypt
3. PBKDF2
Enter the number of your choice: 1
Choose time cost for Argon2id:
1. 2 iterations
2. 4 iterations
3. 6 iterations
4. 12 iterations
Enter the number of your choice: 1
Choose memory cost for Argon2id:
1. 19456 MiB
2. 28672 MiB
3. 37888 MiB
4. 75776 MiB
Enter the number of your choice: 1
Choose operation:
1. Encrypt
2. Decrypt
Enter the number of your choice: 2
Enter password: MySecurePassword!
Enter input data: Bb3DS8N79cJWDAS9IsjNaNRPiXfh2dhPSA6OqdDi1svaEtxp34TNS2HtOULmDmtE6bskMgfIRcubT8q6gSpaefzz
Decrypted Data:
This is a test string.
```
