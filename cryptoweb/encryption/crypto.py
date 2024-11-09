import os
import ctypes
from ctypes import c_char_p, c_int, c_size_t, POINTER, byref, create_string_buffer

# Путь к библиотеке
lib_path = os.path.join(os.path.dirname(__file__), 'lib', 'cryptolib.dll')
cryptolib = ctypes.CDLL(lib_path)

class Crypto:
    def __init__(self):
        # Настройка типов аргументов и возвращаемых типов функций
        cryptolib.generateAESKey.argtypes = [ctypes.POINTER(ctypes.c_ubyte), c_size_t]
        cryptolib.generateIV.argtypes = [ctypes.POINTER(ctypes.c_ubyte), c_size_t]
        
        cryptolib.aesEncrypt.argtypes = [c_char_p, c_size_t, POINTER(ctypes.c_ubyte), POINTER(ctypes.c_ubyte), POINTER(ctypes.c_ubyte)]
        cryptolib.aesEncrypt.restype = c_int

        cryptolib.aesDecrypt.argtypes = [POINTER(ctypes.c_ubyte), c_size_t, POINTER(ctypes.c_ubyte), POINTER(ctypes.c_ubyte), c_char_p]
        cryptolib.aesDecrypt.restype = c_int

    def generate_aes_key(self):
        key = (ctypes.c_ubyte * 16)()  # 128-битный ключ (16 байт)
        cryptolib.generateAESKey(key, 16)
        return bytes(key)

    def generate_iv(self):
        iv = (ctypes.c_ubyte * 16)()  # IV размером 16 байт
        cryptolib.generateIV(iv, 16)
        return bytes(iv)

    def aes_encrypt(self, plaintext, key, iv):
        encrypted = (ctypes.c_ubyte * ((len(plaintext) // 16 + 1) * 16))()  # Буфер для шифрованного текста
        encrypted_len = cryptolib.aesEncrypt(plaintext.encode('utf-8'), len(plaintext), 
                                             (ctypes.c_ubyte * len(key)).from_buffer_copy(key),
                                             (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv), 
                                             encrypted)
        return bytes(encrypted[:encrypted_len])

    def aes_decrypt(self, ciphertext, key, iv):
        decrypted = create_string_buffer(len(ciphertext))  # Буфер для расшифрованного текста
        decrypted_len = cryptolib.aesDecrypt((ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext), 
                                             len(ciphertext), 
                                             (ctypes.c_ubyte * len(key)).from_buffer_copy(key), 
                                             (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv), 
                                             decrypted)
        return decrypted.raw[:decrypted_len].decode('utf-8')
