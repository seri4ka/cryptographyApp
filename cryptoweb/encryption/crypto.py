import os
import ctypes
from ctypes import c_char_p, c_size_t, c_void_p, create_string_buffer, c_ubyte
import base64

# Определяем путь к библиотеке
lib_path = os.path.join(os.path.dirname(__file__), 'lib', 'cryptolib.dll')
cryptolib = ctypes.CDLL(lib_path)

class Crypto:
    def __init__(self):
        self.cryptolib = cryptolib

        # Настраиваем аргументы и возвращаемые значения для RSA функций
        self.cryptolib.rsaEncrypt.argtypes = [c_char_p, c_char_p]
        self.cryptolib.rsaEncrypt.restype = c_void_p

        self.cryptolib.rsaDecrypt.argtypes = [c_char_p, c_char_p]
        self.cryptolib.rsaDecrypt.restype = c_void_p

        # Настраиваем AES
        self.cryptolib.aesEncrypt.argtypes = [c_char_p, ctypes.POINTER(c_ubyte), ctypes.POINTER(c_ubyte)]
        self.cryptolib.aesEncrypt.restype = ctypes.POINTER(c_ubyte)

        self.cryptolib.aesDecrypt.argtypes = [ctypes.POINTER(c_ubyte), c_size_t, ctypes.POINTER(c_ubyte), ctypes.POINTER(c_ubyte)]
        self.cryptolib.aesDecrypt.restype = c_char_p

        # Настраиваем Blowfish
        self.cryptolib.blowfishEncrypt.argtypes = [c_char_p, c_char_p]
        self.cryptolib.blowfishEncrypt.restype = c_void_p

        self.cryptolib.blowfishDecrypt.argtypes = [c_char_p, c_char_p]
        self.cryptolib.blowfishDecrypt.restype = c_void_p

    def encrypt_message_rsa(self, message, public_key):
        # Пример шифрования RSA
        encrypted = create_string_buffer(256)
        self.cryptolib.rsaEncrypt(message.encode('utf-8'), encrypted)
        return base64.b64encode(encrypted.raw).decode('utf-8')

    def decrypt_message_rsa(self, encrypted_message, private_key):
        # Пример дешифрования RSA
        decoded_encrypted = base64.b64decode(encrypted_message)
        decrypted = create_string_buffer(256)
        self.cryptolib.rsaDecrypt(decoded_encrypted, decrypted)
        return decrypted.value.decode('utf-8')

    # Реализация функций для AES и Blowfish
    # Например, aes_encrypt и aes_decrypt могут быть реализованы аналогично
