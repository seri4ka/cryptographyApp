# CryptographyApp

**CryptographyApp** — это приложение на C++, реализующее основные функции шифрования с использованием алгоритмов RSA, Blowfish и AES с поддержкой библиотеки OpenSSL.

## Оглавление
- [Описание](#описание)
- [Функциональные возможности](#функциональные-возможности)
- [Установка](#установка)
- [Использование](#использование)
- [Структура проекта](#структура-проекта)
- [Системные требования](#системные-требования)
- [Сборка и компиляция](#сборка-и-компиляция)
- [Тестирование](#тестирование)
- [Планы по улучшению](#планы-по-улучшению)
- [Лицензия](#лицензия)

## Описание
CryptographyApp — это приложение для демонстрации шифрования и дешифрования данных с использованием популярных алгоритмов RSA, Blowfish и AES. Программа генерирует ключи, шифрует сообщения и дешифрует их, предоставляя простой способ для изучения основ криптографии и реализации шифрования.

## Функциональные возможности
- Генерация ключей для RSA, Blowfish и AES.
- Шифрование и дешифрование сообщений для каждого алгоритма.
- Поддержка кодирования зашифрованных данных в Base64 для удобного хранения и передачи.
- Логирование операций шифрования и дешифрования (в планах).
- Встроенные тесты для проверки корректности каждого алгоритма (в планах).
- Поддержка пользовательского интерфейса (в планах).

## Установка
Для работы с проектом необходимо наличие следующих компонентов:
- [OpenSSL](https://www.openssl.org/) для криптографических операций.
- Компилятор C++ с поддержкой стандарта C++17 или выше.
- [CMake](https://cmake.org/) для сборки проекта.

## Использование
После сборки и запуска приложения программа создаст пары ключей для каждого из алгоритмов и зашифрует тестовые сообщения. Вывод будет включать сгенерированные ключи, зашифрованные сообщения и результаты их дешифровки.

## Структура проекта
CryptographyApp/  
├── include/             # Заголовочные файлы  
├── lib/                 # Внешние библиотеки (например, OpenSSL)  
├── src/                 # Исходные файлы  
│   ├── main.cpp         # Главный файл программы  
│   └── encryption/      # Каталог с реализацией функций шифрования  
│       ├── RSA.cpp      # Реализация RSA шифрования  
│       ├── Blowfish.cpp # Реализация Blowfish шифрования  
│       └── AES.cpp      # Реализация AES шифрования  
├── build/               # Директория для сборки (CMake)  
├── out/                 # Выходные файлы и результаты (например, сгенерированные ключи)  
├── tests/               # Тесты для всех алгоритмов шифрования  
├── CMakeLists.txt       # CMake файл для сборки проекта  
└── README.md            # Описание проекта (текущий файл)  


## Системные требования
- **Операционная система**: Windows, macOS, или Linux
- **Компилятор**: любой, поддерживающий стандарт C++17 (GCC, Clang, MSVC)
- **Зависимости**: OpenSSL

## Сборка и компиляция
1. **Склонируйте репозиторий**:
   ```bash
   git clone <URL вашего репозитория>
   cd CryptographyApp
   ```

2. **Сконфигурируйте и соберите проект с помощью CMake**:
  ```bash
  mkdir build
  cd build
  cmake ..
  cmake --build . --config Release
  ```

3. **Запустите приложение**:
  ```bash
  ./Release/CryptographyApp.exe
  ```

## Тестирование

Для проверки корректности шифрования и дешифрования, приложение будет поддерживать модульные тесты, которые можно запустить после сборки:
  ```bash
  cd build
  ctest
  ```

## Планы по улучшению:

1. **Пользовательский интерфейс**:
- **Qt**: для создания локального графического интерфейса.
- **Веб**: с использованием Flask/Django для серверной части и HTML/CSS/JavaScript для фронтенда.

2. **Логгирование**:
- **Логирование действий** (генерация ключей, шифрование/дешифрование) для отслеживания и диагностики.

3. **Регистрация пользователей**:
- Добавление системы регистрации пользователей в веб-приложении для настройки безопасности.
- Возможная монетизация для предоставления расширенных функций.

4. **Дополнительные алгоритмы и оптимизация кода.**

## Лицензия
Этот проект лицензирован под лицензией MIT. См. файл LICENSE для подробностей.
