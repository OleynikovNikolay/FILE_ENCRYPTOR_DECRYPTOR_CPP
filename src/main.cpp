#include <iostream>
#include <fstream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>

using std::string;
using std::ifstream;
using std::ofstream;
using std::ios;

class fileCipher
{
public:
    string type;
    string action;
    string key;
    string input_file;
    string output_file;

    void XOR_encrypt_decrypt()
    {
        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

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

    // aes encrypting
    void AES_encrypt()
    {
        EVP_CIPHER_CTX* ctx = createEVPContext(true);

        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

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

    void AES_decrypt()
    {
        EVP_CIPHER_CTX* ctx = createEVPContext(false);

        ifstream inputFileStream(input_file, ios::binary);
        ofstream outputFileStream(output_file, ios::binary);

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

private:
    static const int bufferSize = 1024;

    // error handler
    void handleError(const string& errorMsg)
    {
        std::cerr << errorMsg << std::endl;
        
        ERR_print_errors_fp(stderr);
    }

    // EVP_CIPHER_CTX pointer for EVP context creation -> isEncrypt creates dynamic choice of encrypting/decrypting context
    EVP_CIPHER_CTX* createEVPContext(bool isEncrypt)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        // error validation if EVP context git could be created
        if (!ctx)
        {
            handleError("Failed to create EVP context.");
            return nullptr;
        }

        const unsigned char* encryption_key = reinterpret_cast<const unsigned char*>(key.c_str());
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
    void processAES(ifstream& input, ofstream& output, EVP_CIPHER_CTX* &ctx)
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

    void closeStreams(ifstream& input, ofstream& output)
    {
        input.close();
        output.close();
    }

    // cleaning up pointers
    void cleanupEVPContext(EVP_CIPHER_CTX* ctx)
    {
        if (ctx != nullptr)
        {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

// converting to lower 
void toLower(char* str)
{
    while (*str)
    {
        *str = tolower(*str);
        str++;
    }
}

// validating number of input arguments
bool isValid_size(int argc)
{
    return argc == 6;
}

// validating decryption/encryption method 
bool isValid_method(char* argv[])
{
    return (strcmp(argv[1], "-aes") == 0 || strcmp(argv[1], "-xor") == 0);
}

// validating action
bool isValid_action(char* argv[])
{
    return (strcmp(argv[2], "-decrypt") == 0 || strcmp(argv[2], "-encrypt") == 0);
}


// decrypt-encrypt-tool -aes -decrypt key inputfile outputfile 
int main(int argc, char* argv[])
{
    // only first 3 arguments are lowered the key should not be lowered
    for (int i = 0; i < 2; ++i)
    {
        toLower(argv[i]);
    }

    bool validitySize = isValid_size(argc);
    bool validityMethod = isValid_method(argv);
    bool validityAction = isValid_action(argv);

    if (!validitySize)
    {
        std::cerr << "Usage: " << argv[0] << " -aes|-xor -decrypt|-encrypt key inputfile outputfile" << std::endl;
        return EXIT_FAILURE;
    }

    if (!validityMethod)
    {
        std::cerr << "Not valid decryption/encryption method." << std::endl;
        return EXIT_FAILURE;
    }

    if (!validityAction)
    {
        std::cerr << "Not valid action." << std::endl;
        return EXIT_FAILURE;
    }
    fileCipher fileObject;

    fileObject.type = argv[1];
    fileObject.action = argv[2];
    fileObject.key = argv[3];
    fileObject.input_file = argv[4];
    fileObject.output_file = argv[5];

    std:: cout << fileObject.key << std::endl;

    if (fileObject.type == "-aes")
    {
        if (fileObject.action == "-decrypt")
        {
            fileObject.AES_decrypt();
        } else
        {
            fileObject.AES_encrypt();
        }
    } else
    {
        fileObject.XOR_encrypt_decrypt();
    }
    return EXIT_SUCCESS;
};