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
3. Change the directory for binary file usage
`cd bin `


# Usage 
```
./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -aes|-xor -encrypt|-decrypt "key" "inputFilePath" "outputFilePath" 
```
When using AES ensure that the encryption key is 256 bits long.

# License 
MIT License 


