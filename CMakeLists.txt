cmake_minimum_required(VERSION 3.10)
project(cryptolib)

# Определяем стандарт C++
set(CMAKE_CXX_STANDARD 17)

# Пути к исходным файлам
set(SOURCES
    src/encryption/RSA.cpp
    src/encryption/Blowfish.cpp
    src/encryption/AES.cpp
)

# Пути к заголовочным файлам
set(HEADERS
    src/encryption//RSA.h
    src/encryption//Blowfish.h
    src/encryption//AES.h
)

# Создаем динамическую библиотеку
add_library(cryptolib SHARED ${SOURCES} ${HEADERS})

# Подключаем OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(cryptolib OpenSSL::SSL OpenSSL::Crypto)

# Устанавливаем путь к заголовочным файлам
target_include_directories(cryptolib PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Устанавливаем путь для сборки библиотеки (output directory)
set_target_properties(cryptolib PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib
)

# Обеспечиваем правильную установку экспортных символов для Windows
if (WIN32)
    target_compile_definitions(cryptolib PRIVATE EXPORTS)
endif()
