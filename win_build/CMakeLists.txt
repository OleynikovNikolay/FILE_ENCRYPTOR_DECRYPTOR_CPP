cmake_minimum_required(VERSION 3.0)
set(CMAKE_SYSTEM_NAME Windows)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/../lib)
set(CMAKE_FIND_ROOT_PATH
    "/opt/homebrew/Cellar/mingw-w64/11.0.1/toolchain-x86_64/x86_64-w64-mingw32/bin"
)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)


set(EXE_NAME SECURECRYPT-FILE-ENCRYPTION-DECRYPTION-TOOL)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)

project(${EXE_NAME} VERSION 1.0)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin/win)


set(SOURCE_FILES
    ${CMAKE_SOURCE_DIR}/../src/cipherValidation.cpp
    ${CMAKE_SOURCE_DIR}/../src/commandHandlers.cpp
    ${CMAKE_SOURCE_DIR}/../src/fileCipher.cpp
    ${CMAKE_SOURCE_DIR}/../src/main.cpp
)


add_executable(${EXE_NAME} ${SOURCE_FILES})


set_target_properties(${EXE_NAME} PROPERTIES
    COMPILE_FLAGS "-m64"
    LINK_FLAGS "-m64"
)


set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")


find_package(OpenSSL REQUIRED)


if(OPENSSL_FOUND)
    include_directories(${CMAKE_SOURCE_DIR}/../lib)
    link_directories(${OPENSSL_INSTALL_DIR}/lib)
    target_link_libraries(${EXE_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
else()
    message(FATAL_ERROR "OpenSSL not found. Ensure OpenSSL is correctly installed and specified in OPENSSL_ROOT_DIR.")
endif()


target_include_directories(${EXE_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../include)
