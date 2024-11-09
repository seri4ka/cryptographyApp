from django.http import JsonResponse
from .crypto import Crypto

crypto = Crypto()

def encrypt_message(request):
    plaintext = request.GET.get('message', 'Hello, AES encryption!')
    key = crypto.generate_aes_key()
    iv = crypto.generate_iv()
    encrypted_message = crypto.aes_encrypt(plaintext, key, iv)
    return JsonResponse({
        'encrypted': encrypted_message.hex(),
        'key': key.hex(),
        'iv': iv.hex()
    })

def decrypt_message(request):
    encrypted_hex = request.GET.get('encrypted')
    if encrypted_hex is None:
        return JsonResponse({'error': 'Encrypted message not provided'}, status=400)
    
    encrypted_message = bytes.fromhex(encrypted_hex)
    key = bytes.fromhex(request.GET.get('key'))
    iv = bytes.fromhex(request.GET.get('iv'))
    
    # Остальная часть кода для расшифровки
    decrypted_message = crypto.aes_decrypt(encrypted_message, key, iv)
    return JsonResponse({'decrypted': decrypted_message})

