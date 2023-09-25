/*
This header declares small inline utility functions.
*/

#include <cstring>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

#ifndef SECURE_CRYPT_UTILS_H
#define SECURE_CRYPT_UTILS_H

// converting to lower 
inline void toLower(char* str)
{
    while (*str)
    {
        *str = tolower(*str);
        str++;
    }
}


// validating number of input arguments
inline bool isValid_size(int argc)
{
    return argc == 6;
}

// validating decryption/encryption method 
inline bool isValid_method(char* argv[])
{
    return (strcmp(argv[1], "-aes") == 0 || strcmp(argv[1], "-xor") == 0);
}

// validating action
inline bool isValid_action(char* argv[])
{
    return (strcmp(argv[2], "-decrypt") == 0 || strcmp(argv[2], "-encrypt") == 0);
}

// key validation - 64 bytes hexadecimal string
inline bool isValid_key(char* argv[])
{
    if (strcmp(argv[1], "-aes") == 0)
    {
        std::string key = argv[3];
        return key.size() == 64 && std::all_of(key.begin(), key.end(), ::isxdigit);
    }
    return true;
}

// converting hexadecimal 64 bytes to 32 bytes key
inline const unsigned char* hexStringToKey(const std::string& hexString) {
    if (hexString.size() != 64) {
        std::cerr << "Invalid input key size." << std::endl;
        return nullptr;
    }

    static unsigned char key[32];

    for (size_t i = 0; i < 32; ++i) {
        int byteValue;
        std::string byteString = hexString.substr(i * 2, 2);
        std::sscanf(byteString.c_str(), "%02x", &byteValue);
        key[i] = static_cast<unsigned char>(byteValue);
    }

    return key;
}

// converting hexadecimal 32 bytes key to 64 bytes hexadecimal
inline std::string const keyToHexString(unsigned char* key, int keySize)
{
    std::stringstream ss;
    for (int i = 0; i < keySize; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
    }
    return ss.str();
}

#endif //SECURE_CRYPT_UTILS_H