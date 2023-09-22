# SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL

This is CLI application allowing users to use two different encrypting algorithms: `AES (256 - CBC)`, `XOR` for encrypting/decrypting their files. 


# Installation
1. Clone the repo
```
git clone https://github.com/OleynikovNikolay/SecureCrypt-File-Encryption-Decryption-Tool
cd SecureCrypt-File-Encryption-Decryption-Tool
```
2. Compile with CMake 
``` 
cmake .
make
```
3. Change directory for binary file path
```
cd bin
```


# Usage 
## Navigation Page
```
./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -help
```

## Random AES256 key generation
```
./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -generate-aes256-key
```

## File decryption/encryption
```
./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -aes|-xor -encrypt|-decrypt "key" "inputFilePath" "outputFilePath" 
```
When using AES ensure that the encryption key is 256 bits long. You may use `-generate-aes256-key` command.

# License 
MIT License 


