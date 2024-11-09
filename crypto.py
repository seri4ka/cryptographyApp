import ctypes
from ctypes import c_char_p

# Загрузите вашу библиотеку
crypto_lib = ctypes.CDLL('./cryptography_lib/build/cryptography_lib.dll')  # для Windows
# crypto_lib = ctypes.CDLL('./cryptography_lib/build/libcryptography_lib.so')  # для Linux

# Укажите возвращаемые типы
crypto_lib.rsaEncrypt.restype = c_char_p
crypto_lib.rsaDecrypt.restype = c_char_p

def rsa_encrypt(message, public_key_path):
    result = crypto_lib.rsaEncrypt(message.encode('utf-8'), public_key_path.encode('utf-8'))
    return result.decode('utf-8')

def rsa_decrypt(encrypted_message, private_key_path):
    result = crypto_lib.rsaDecrypt(encrypted_message.encode('utf-8'), private_key_path.encode('utf-8'))
    return result.decode('utf-8')
