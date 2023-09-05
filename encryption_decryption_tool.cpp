#include <iostream>
#include <fstream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using std::string;
using std::ifstream;
using std::ofstream;
using std::ios;

class File
{
public:
    string action;
    string type;
    string input_file;
    string output_file;

    void XOR_encrypt_decrypt(char key)
    {
        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

        if (!inputFileStream || !outputFileStream)
        {
            handleError("Failed to open files!");
            return;
        }

        char byte;
        while (inputFileStream.get(byte))
        {
            byte ^= key;
            outputFileStream.put(byte);
        }

        closeStreams(inputFileStream, outputFileStream);
    }

    void AES_encrypt(string key)
    {
        EVP_CIPHER_CTX* ctx = createEVPContext(key, true);

        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

        if (!inputFileStream || !outputFileStream || !ctx)
        {
            handleError("Failed to initialize AES encryption.");
            return;
        }

        processAES(inputFileStream, outputFileStream, ctx);

        closeStreams(inputFileStream, outputFileStream);
        cleanupEVPContext(ctx);
    }

    void AES_decrypt(string key)
    {
        EVP_CIPHER_CTX* ctx = createEVPContext(key, false);

        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

        if (!inputFileStream || !outputFileStream || !ctx)
        {
            handleError("Failed to initialize AES decryption.");
            return;
        }

        processAES(inputFileStream, outputFileStream, ctx);

        closeStreams(inputFileStream, outputFileStream);
        cleanupEVPContext(ctx);
    }

private:
    static const int bufferSize = 1024;

    void handleError(const string& errorMsg)
    {
        std::cerr << errorMsg << std::endl;
    }

    EVP_CIPHER_CTX* createEVPContext(const string& key, bool isEncrypt)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            handleError("Failed to create EVP context.");
            return nullptr;
        }

        const unsigned char* encryption_key = reinterpret_cast<const unsigned char*>(key.c_str());
        const EVP_CIPHER* cipherType = isEncrypt ? EVP_aes_256_cbc() : EVP_aes_256_cbc();

        if (EVP_CipherInit_ex(ctx, cipherType, nullptr, encryption_key, nullptr, isEncrypt ? 1 : 0) != 1)
        {
            handleError(isEncrypt ? "Failed to initialize AES encryption." : "Failed to initialize AES decryption.");
            cleanupEVPContext(ctx);
            return nullptr;
        }

        return ctx;
    }

    void processAES(ifstream& input, ofstream& output, EVP_CIPHER_CTX* ctx)
    {
        unsigned char inBuf[bufferSize];
        unsigned char outBuf[bufferSize];
        int bytesRead;
        int processedBytes;

        while ((bytesRead = input.readsome(reinterpret_cast<char*>(inBuf), sizeof(inBuf))))
        {
            if (EVP_CipherUpdate(ctx, outBuf, &processedBytes, inBuf, bytesRead) != 1)
            {
                handleError("Failed to perform AES operation.");
                cleanupEVPContext(ctx);
                return;
            }
            output.write(reinterpret_cast<char*>(outBuf), processedBytes);
        }

        if (EVP_CipherFinal_ex(ctx, outBuf, &processedBytes) != 1)
        {
            handleError("Failed to finalize AES operation.");
            cleanupEVPContext(ctx);
            return;
        }

        output.write(reinterpret_cast<char*>(outBuf), processedBytes);
    }

    void closeStreams(ifstream& input, ofstream& output)
    {
        input.close();
        output.close();
    }

    void cleanupEVPContext(EVP_CIPHER_CTX* ctx)
    {
        if (ctx)
        {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

int main()
{
    return 0;
};