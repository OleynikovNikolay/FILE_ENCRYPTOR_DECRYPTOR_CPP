# SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL

This is CLI application allowing users to use two different encrypting algorithms: `AES (256 - CBC)`, `XOR` for encrypting/decrypting their files. 


# Installation
## CMake MacOS (ARM 64)
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
## Windows (64bit)
1. Clone the repo
```
git clone https://github.com/OleynikovNikolay/SecureCrypt-File-Encryption-Decryption-Tool
cd SecureCrypt-File-Encryption-Decryption-Tool
```
2. Navigate to .exe
``` 
cd bin
cd win
```
3. Call executable
```
SecureCrypt-File-Encryption-Decryption-Tool.exe
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
Key generated is hexadecimal representation of 32 bytes key. 

## File decryption/encryption
```
./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -aes|-xor -encrypt|-decrypt "key" "inputFilePath" "outputFilePath" 
```
When using AES ensure that the encryption key is hexadecimal (64 bytes) representation of 32 bytes key. You may use `-generate-aes256-key` command.

# License 
MIT License 


