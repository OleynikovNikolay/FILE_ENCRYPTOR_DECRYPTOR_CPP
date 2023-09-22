
#include "../include/utils.h"
#include "../include/fileCipher.cpp"
#include <string>



// SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -aes -decrypt "key" "inputfile" "outputfile" 
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

    std::string type = argv[1];
    std::string action = argv[2];
    std::string key = argv[3]; 
    std::string input_file = argv[4];
    std::string output_file = argv[5];

    fileCipher fileObject(type, action, key, input_file, output_file);

    if (fileObject.getType() == "-aes")
    {
        if (fileObject.getAction() == "-decrypt")
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