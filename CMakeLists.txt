cmake_minimum_required(VERSION 3.0)

project(SecureCrypt-File-Encryption-Decryption-Tool VERSION 1.0)

find_package(OpenSSL REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(main_executable src/main.cpp)

target_link_libraries(main_executable PRIVATE OpenSSL::SSL OpenSSL::Crypto)


