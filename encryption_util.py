import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


KEY = b'Sixteen byte key'
BLOCK_SIZE = 128

def encrypt_message(message: str) -> str:

    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted = iv + ciphertext
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message: str) -> str:

    encrypted_data = base64.b64decode(encrypted_message)

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')

def encrypt_data(data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_data(encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data
