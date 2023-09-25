/*
This cpp defines the implementation of fileCipher class.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include "../include/fileCipher.h"
#include "../include/utils.h"

fileCipher::fileCipher(const std::string& type, const std::string& action, const std::string& key, const std::string& input_file, const std::string& output_file)
    : type(type), action(action), key(key), input_file(input_file), output_file(output_file) {
}

void fileCipher::XOR_encrypt_decrypt()
{
    std::ifstream inputFileStream(input_file, std::ios::binary);
    std::ofstream outputFileStream(output_file, std::ios::binary);

    if (!inputFileStream || !outputFileStream)
    {
        handleError("Failed to open files!");
        return;
    }

    char byte;
    std::size_t keyLength = key.length();
    std::size_t keyIndex = 0;

    while (inputFileStream.get(byte))
    {
        byte ^= key[keyIndex];
        outputFileStream.put(byte);

        keyIndex = (keyIndex + 1) % keyLength;
    }

    closeStreams(inputFileStream, outputFileStream);
}


void fileCipher::AES_encrypt()
{
    EVP_CIPHER_CTX* ctx = createEVPContext(true);

    std::ifstream inputFileStream(input_file, std::ios::binary);
    std::ofstream outputFileStream(output_file, std::ios::binary);

    if (!inputFileStream || !outputFileStream || !ctx)
    {
        handleError("Failed to initialize AES encryption.");
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 1); // padding PKCS#7

    processAES(inputFileStream, outputFileStream, ctx);

    closeStreams(inputFileStream, outputFileStream);
    cleanupEVPContext(ctx);
}


void fileCipher::AES_decrypt()
{
    EVP_CIPHER_CTX* ctx = createEVPContext(false);

    std::ifstream inputFileStream(input_file, std::ios::binary);
    std::ofstream outputFileStream(output_file, std::ios::binary);

    if (!inputFileStream || !outputFileStream || !ctx)
    {
        handleError("Failed to initialize AES decryption.");
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 1); // padding PKCS#7

    processAES(inputFileStream, outputFileStream, ctx);

    closeStreams(inputFileStream, outputFileStream);
    cleanupEVPContext(ctx);
}


void fileCipher::handleError(const std::string& errorMsg)
{
    std::cerr << errorMsg << std::endl;
    
    ERR_print_errors_fp(stderr);
}

// creating EVP context
EVP_CIPHER_CTX* fileCipher::createEVPContext(bool isEncrypt)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // error validation if EVP context git could be created
    if (!ctx)
    {
        handleError("Failed to create EVP context.");
        return nullptr;
    }

    //const unsigned char* encryption_key = reinterpret_cast<const unsigned char*>(key.c_str());
    const unsigned char* encryption_key = hexStringToKey(key);
    
    const EVP_CIPHER* cipherType = isEncrypt ? EVP_aes_256_cbc() : EVP_aes_256_cbc();

    // generating static iv
    const unsigned char static_iv[EVP_MAX_IV_LENGTH] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

    // initialising EVP decryption/encryption based on isEncrypt
    if (EVP_CipherInit_ex(ctx, cipherType, nullptr, encryption_key, static_iv, isEncrypt ? 1 : 0) != 1)
    {
        handleError(isEncrypt ? "Failed to initialize AES encryption." : "Failed to initialize AES decryption.");
        cleanupEVPContext(ctx);
        return nullptr;
    }

    return ctx;
}

// encrypting/decrypting files based on EVP_cipher_ctx context
void fileCipher::processAES(std::ifstream& input, std::ofstream& output, EVP_CIPHER_CTX* &ctx)
{
    unsigned char inBuf[bufferSize];
    unsigned char outBuf[bufferSize];
    int bytesRead;
    int processedBytes;

    while (input)
    {
        input.read(reinterpret_cast<char*>(inBuf), sizeof(inBuf));
        int bytesRead = input.gcount();

        if (bytesRead == 0)
        {
            break;
        }

        if (EVP_CipherUpdate(ctx, outBuf, &processedBytes, inBuf, bytesRead) != 1)
        {
            handleError("Failed to perform AES operation.");
            cleanupEVPContext(ctx);
            ctx = nullptr;
            return;
        }

        output.write(reinterpret_cast<char*>(outBuf), processedBytes);
    }

    if (EVP_CipherFinal_ex(ctx, outBuf, &processedBytes) != 1)
    {
        handleError("Failed to finalize AES operation!");
        cleanupEVPContext(ctx);
        ctx = nullptr;
        return;
    }

    output.write(reinterpret_cast<char*>(outBuf), processedBytes);
}

// closing off streams
void fileCipher::closeStreams(std::ifstream& input, std::ofstream& output)
{
    input.close();
    output.close();
}

// cleaning up pointers
void fileCipher::cleanupEVPContext(EVP_CIPHER_CTX* ctx)
{
    if (ctx != nullptr)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
}