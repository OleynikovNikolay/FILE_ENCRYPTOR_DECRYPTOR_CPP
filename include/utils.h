/*
This header declares small inline utility functions.
*/

#include <cstring>
#include <string>

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

// key validation 
inline bool isValid_key(char* argv[])
{
    if (strcmp(argv[1], "-aes") == 0)
    {
        std::string key = argv[3];
        return key.size() == 64 && std::all_of(key.begin(), key.end(), ::isxdigit);
    }
    return true;
}

#endif //SECURE_CRYPT_UTILS_H