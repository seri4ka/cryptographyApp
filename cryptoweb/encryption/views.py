from django.shortcuts import render
from .forms import EncryptDecryptForm
from .crypto import Crypto

crypto = Crypto()

def encrypt_decrypt_view(request):
    form = EncryptDecryptForm()
    result = None
    if request.method == 'POST':
        form = EncryptDecryptForm(request.POST)
        if form.is_valid():
            message = form.cleaned_data['message']
            algorithm = form.cleaned_data['algorithm']
            action = form.cleaned_data['action']
            if algorithm == 'RSA':
                if action == 'encrypt':
                    result = crypto.encrypt_message_rsa(message, 'path_to_public_key')
                elif action == 'decrypt':
                    result = crypto.decrypt_message_rsa(message, 'path_to_private_key')
            # Аналогично для других алгоритмов
    return render(request, 'encryption/encrypt_decrypt.html', {'form': form, 'result': result})

