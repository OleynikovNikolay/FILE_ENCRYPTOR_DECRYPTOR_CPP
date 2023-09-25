#include <string>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include "../include/utils.h"
#include "../include/fileCipher.h"



// showing help navigation
void showHelp()
{
    std::cout << "Options:" << std::endl;
    std::cout << "  ./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL [-help; -aes; -xor; -generate-aes256-key]" << std::endl;
    std::cout << "  -help                         Shows navigation page." << std::endl;
    std::cout << "                                Usage: -help" << std::endl;
    std::cout << "  -aes|-xor                     Decrypts/encrypts the file." << std::endl;
    std::cout << "                                Usage: -aes|-xor -decrypt|-encrypt key inputfile outputfile" << std::endl;
    std::cout << "  -generate-aes256-key          Generates a random AES256-size key (hexadecimal - 64 bytes for 32 bytes key)." << std::endl;
    std::cout << "                                Usage: -generate-aes256-key" << std::endl;
}

// processing files for encryption/decryption
void executeFileCipher(int argc, char* argv[])
{
    // only first 3 arguments are lowered the key should not be lowered
    for (int i = 0; i < 2; ++i)
    {
        toLower(argv[i]);
    }

    bool validitySize = isValid_size(argc);
    bool validityMethod = isValid_method(argv);
    bool validityAction = isValid_action(argv);
    bool validityKey = isValid_key(argv);

    if (!validitySize)
    {
        std::cerr << "Usage: " << argv[0] << " -aes|-xor -decrypt|-encrypt key inputfile outputfile" << std::endl;
        return;
    }

    if (!validityMethod)
    {
        std::cerr << "Not valid decryption/encryption method." << std::endl;
        return;
    }

    if (!validityAction)
    {
        std::cerr << "Not valid action." << std::endl;
        return;
    }

    if(!validityKey)
    {
        std::cerr << "Not valid AES256 key: use -generate-aes256-key to generate valid key." << std::endl;
        return;
    }

    std::string type = argv[1];
    std::string action = argv[2];
    std::string key = argv[3];
    std::string input_file = argv[4];
    std::string output_file = argv[5];

    fileCipher fileObject(type, action, key, input_file, output_file);

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
}


// generating random aes256 key 
void generateAES256Key()
{
    const int keySize = 256 / 8; 
    unsigned char key[keySize];

    if (RAND_bytes(key, keySize) != 1) {
        std::cerr << "Error generating random key." << std::endl;
        return;
    }

    std::string hexaString = keyToHexString(key, keySize);

    std::cout << "Hexadecimal presentation (64 bytes) of random AES 256 key (32 bytes) has been generated:" << std::endl;
    std::cout << hexaString << std::endl;
}