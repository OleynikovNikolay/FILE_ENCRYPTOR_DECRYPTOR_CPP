# Use an official CMake image as the base image
FROM ubuntu:latest

# setting the working directory inside the container
WORKDIR /app

# installing CMake 
RUN apt-get update && apt-get install -y cmake g++

# creating the target directory for the binary (if it doesn't exist)
RUN mkdir -p /app/bin/mac

# copying the CMakeLists.txt to the container
COPY mac_build/CMakeLists.txt /app/mac_build/CMakeLists.txt

# copying the source code to the container
COPY src /app/src

# copying the include directory to the container
COPY include /app/include

# setting the working directory to the build directory
WORKDIR /app/mac_build/

# building the C++ application using CMake and make
RUN cmake . && \
    make

# setting the entry point of the container (you can modify this as needed)
CMD ["/app/bin/mac/SecureCrypt-File-Encryption-Decryption-Tool"]
