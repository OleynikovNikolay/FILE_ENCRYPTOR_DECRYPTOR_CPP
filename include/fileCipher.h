/*
This header declares fileCipher class, its attributes and its methods.
*/

#include <string> 
#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifndef FILE_CIPHER_H
#define FILE_CIPHER_H


class fileCipher
{
public:
    std::string type;
    std::string action;
    std::string key;
    std::string input_file;
    std::string output_file;

    fileCipher(const std::string& type, const std::string& action, const std::string& key, const std::string& input_file, const std::string& output_file);

    // xor encryption/decryption
    void XOR_encrypt_decrypt();

    // aes encryption
    void AES_encrypt();

    // aes decryption
    void AES_decrypt();

private:
    static const int bufferSize = 1024;

    // error handler
    void handleError(const std::string& errorMsg);

    // EVP_CIPHER_CTX pointer for EVP context creation -> isEncrypt creates dynamic choice of encrypting/decrypting context
    EVP_CIPHER_CTX* createEVPContext(bool isEncrypt);

    // encrypting/decrypting files based on EVP_cipher_ctx context
    void processAES(std::ifstream& input, std::ofstream& output, EVP_CIPHER_CTX* &ctx);

    // closing streams
    void closeStreams(std::ifstream& input, std::ofstream& output);

    // cleaning up pointers
    void cleanupEVPContext(EVP_CIPHER_CTX* ctx);
};


#endif //FILE_CIPHER_H