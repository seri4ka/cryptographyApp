from django import forms

class EncryptDecryptForm(forms.Form):
    message = forms.CharField(widget=forms.Textarea, label="Сообщение для шифрования:")
    algorithm = forms.ChoiceField(choices=[('RSA', 'RSA'), ('Blowfish', 'Blowfish'), ('AES', 'AES')], label="Алгоритм:")
    action = forms.ChoiceField(choices=[('encrypt', 'Шифровать'), ('decrypt', 'Дешифровать')], label="Действие:")
