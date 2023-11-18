cmake_minimum_required(VERSION 3.0)
set(CMAKE_SYSTEM_NAME Windows)


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


set(CMAKE_FIND_ROOT_PATH
   "/opt/homebrew/Cellar/mingw-w64/11.0.1/toolchain-x86_64/x86_64-w64-mingw32/bin"
)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)

set(EXE_NAME SecureCrypt-File-Encryption-Decryption-Tool)

set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

project(${EXE_NAME} VERSION 1.0)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin/win)


set(SOURCE_FILES
    ../src/cipherValidation.cpp
    ../src/commandHandlers.cpp
    ../src/fileCipher.cpp
    ../src/main.cpp
)

add_executable(${EXE_NAME} ${SOURCE_FILES})

set_target_properties(${EXE_NAME} PROPERTIES
    COMPILE_FLAGS "-m64"
    LINK_FLAGS "-m64"
)


target_include_directories(${EXE_NAME} PRIVATE
    ../include
)


set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static -L/Users/nik/lib/openssl -lcrypto -lssl")

set(OPENSSL_ROOT_DIR "/Users/nik/lib/openssl")
find_package(OpenSSL REQUIRED)

target_link_libraries(${EXE_NAME} PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
    -static-libgcc
    -static-libstdc++
    -static
)

target_include_directories(${EXE_NAME} PRIVATE ../include)