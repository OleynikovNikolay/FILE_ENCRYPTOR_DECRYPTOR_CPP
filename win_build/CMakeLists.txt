cmake_minimum_required(VERSION 3.0)
set(CMAKE_SYSTEM_NAME Windows)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specify the location of OpenSSL and Mingw-w64 toolchain
set(OPENSSL_ROOT_DIR "/opt/homebrew/Cellar/openssl@3/3.1.4")
set(CMAKE_FIND_ROOT_PATH
    "/opt/homebrew/Cellar/mingw-w64/11.0.1/toolchain-x86_64/x86_64-w64-mingw32/bin"
)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)

# Project setup
set(EXE_NAME SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

project(SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL VERSION 1.0)

# Set the output directory for the Windows executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin/win)

# Define your source files
set(SOURCE_FILES
    ../src/cipherValidation.cpp
    ../src/commandHandlers.cpp
    ../src/fileCipher.cpp
    ../src/main.cpp
)

# Create the executable
add_executable(${EXE_NAME} ${SOURCE_FILES})

# Compiler and linker flags for 64-bit build
set_target_properties(${EXE_NAME} PROPERTIES
    COMPILE_FLAGS "-m64"
    LINK_FLAGS "-m64"
)

# Static linking flags for the Mingw-w64 toolchain
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")

# Find and link with OpenSSL
find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)

# Check if OpenSSL was found
if(OPENSSL_FOUND)
    # Link with OpenSSL components
    target_link_libraries(${EXE_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
else()
    message(FATAL_ERROR "OpenSSL not found. Ensure OpenSSL is correctly installed and specified in OPENSSL_ROOT_DIR.")
endif()

# Include directories
target_include_directories(${EXE_NAME} PRIVATE ../include)
