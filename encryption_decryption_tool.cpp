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
        if(!inputFileStream || !outputFileStream)
        {
            std::cerr << "Failed to open files!" << std::endl;
            return;
        }

        char byte;
        while(inputFileStream.get(byte))
        // flipping bits between byte and key value - bitwise operation
        {
            byte ^= key;
            outputFileStream.put(byte);
        }

        inputFileStream.close();
        outputFileStream.close();

    }

    void AES_encrypt(string key)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        // context validation
        if (!ctx) {
            std::cerr << "Failed to create EVP context." << std::endl;
            return;
        }
        // conversion to array of pointers (cstring) - null terminated
        const unsigned char* encryption_key = reinterpret_cast<const unsigned char*>(key.c_str());

        // initialisiing encryption and checking if it is successful - if not, clearing memory
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryption_key, NULL) != 1) {
            std::cerr << "Failed to initialize AES encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        // reading files in in and out strea,
        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

        // validation if streaming has been successful
        if (!inputFileStream || !outputFileStream) {
            std::cerr << "Failed to open files!" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        // arrays creation size - 1024 - each of item may hold 8 bit value
        unsigned char inBuf[1024];
        unsigned char outBuf[1024];
        int bytesRead;
        int encryptedBytes;

        // reading input file stream, encrypting it into outBuf
        while ((bytesRead = inputFileStream.readsome(reinterpret_cast<char*>(inBuf), sizeof(inBuf)))) {
            if (EVP_EncryptUpdate(ctx, outBuf, &encryptedBytes, inBuf, bytesRead) != 1) {
                std::cerr << "Failed to perform AES encryption." << std::endl;
                EVP_CIPHER_CTX_free(ctx);
                return;
            }
            outputFileStream.write(reinterpret_cast<char*>(outBuf), encryptedBytes);
        }

        // finalising encryption 
        if (EVP_EncryptFinal_ex(ctx, outBuf, &encryptedBytes) != 1) {
            std::cerr << "Failed to finalize AES encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        // writing into outBuf finished encrypted bytes
        outputFileStream.write(reinterpret_cast<char*>(outBuf), encryptedBytes);

        // freeing up the memory
        EVP_CIPHER_CTX_free(ctx);


        // closing off the streams
        inputFileStream.close();
        outputFileStream.close();

    }

    void AES_decrypt(string key)
    {

    }

};

int main()
{
    return 0;
}

