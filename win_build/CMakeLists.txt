cmake_minimum_required(VERSION 3.0)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL VERSION 1.0)

# Set the MinGW toolchain
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

# Set the output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin/win)

# Source files
set(SOURCE_FILES
    ${CMAKE_SOURCE_DIR}/../src/cipherValidation.cpp
    ${CMAKE_SOURCE_DIR}/../src/commandHandlers.cpp
    ${CMAKE_SOURCE_DIR}/../src/fileCipher.cpp
    ${CMAKE_SOURCE_DIR}/../src/main.cpp
)

# Create the executable
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

# Set compiler and linker flags
set_target_properties(${PROJECT_NAME} PROPERTIES
    COMPILE_FLAGS "-m64"
    LINK_FLAGS "-m64"
)

# Set specific linker flags for static linking
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    # Include and link against OpenSSL
    include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_LIBRARIES})
else()
    message(FATAL_ERROR "OpenSSL not found. Ensure OpenSSL is correctly installed and specified in OPENSSL_ROOT_DIR.")
endif()

# Include additional directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../lib  # Add the lib directory if necessary
)
