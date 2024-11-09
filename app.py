# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, jsonify
from crypto import rsa_encrypt, rsa_decrypt

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message')
    algorithm = data.get('algorithm')
    
    if algorithm == 'rsa':
        result = rsa_encrypt(message, 'path/to/public_key.pem')
        return jsonify({'encrypted_message': result})
    # Добавьте вызовы для Blowfish и AES аналогично
    return jsonify({'error': 'Algorithm not supported'})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_message = data.get('encrypted_message')
    algorithm = data.get('algorithm')
    
    if algorithm == 'rsa':
        result = rsa_decrypt(encrypted_message, 'path/to/private_key.pem')
        return jsonify({'decrypted_message': result})
    # Добавьте вызовы для Blowfish и AES аналогично
    return jsonify({'error': 'Algorithm not supported'})

if __name__ == '__main__':
    app.run(debug=True)
