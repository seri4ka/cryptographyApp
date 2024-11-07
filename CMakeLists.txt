cmake_minimum_required(VERSION 3.10)
project(CryptographyApp)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(CryptographyApp src/main.cpp src/encryption/RSA.cpp src/encryption/Blowfish.cpp src/applink.c)


target_link_libraries(CryptographyApp ${OPENSSL_LIBRARIES})

