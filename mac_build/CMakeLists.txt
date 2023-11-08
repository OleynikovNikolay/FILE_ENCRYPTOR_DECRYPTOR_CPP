cmake_minimum_required(VERSION 3.0)

project(SecureCrypt-File-Encryption-Decryption-Tool VERSION 1.0)

find_package(OpenSSL REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin/mac)

add_executable(SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL 
                    ../src/main.cpp
                    ../src/fileCipher.cpp
                    ../src/commandHandlers.cpp
                    ../src/cipherValidation.cpp)

target_include_directories(SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL PRIVATE ../include)


target_link_libraries(SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL PRIVATE OpenSSL::SSL OpenSSL::Crypto)
