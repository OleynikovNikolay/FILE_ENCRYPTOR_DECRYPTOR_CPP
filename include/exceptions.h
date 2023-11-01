/*
This header declares custom exception classes.
*/

#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <stdexcept>

class SizeException : public std::runtime_error {
public:
    SizeException() : std::runtime_error("Usage: ./SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL -aes|-xor -decrypt|-encrypt key inputfile outputfile") {}
};

class MethodException : public std::runtime_error {
public:
    MethodException() : std::runtime_error("Not valid decryption/encryption method.") {}
};

class ActionException : public std::runtime_error {
public:
    ActionException() : std::runtime_error("Not valid action.") {}
};

class KeyException : public std::runtime_error {
public:
    KeyException() : std::runtime_error("Not valid AES256 key: use -generate-aes256-key to generate valid key.") {}
};

#endif //EXCEPTIONS_H