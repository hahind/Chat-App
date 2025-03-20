import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#AES CBC mode encryption/decryption for strings
class EncryptionUtil:

    def __init__(self, key: bytes = b'Sixteen byte key', block_size: int = 128):

        self.key = key
        self.block_size = block_size
        self.backend = default_backend()
#encrypt text using AES in CBC mode.
    def encrypt_message(self, message: str) -> str:

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        encrypted = iv + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')
# Decrypt string msg using AES in CBC mode.
    def decrypt_message(self, encrypted_message: str) -> str:

        encrypted_data = base64.b64decode(encrypted_message)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(self.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode('utf-8')
    
# Encrypt data using AES in CBC mode, returns bytes.
    def encrypt_data(self, data: bytes) -> bytes:

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    
# Decrypt data that was encrypted via AES in CBC mode.
    def decrypt_data(self, encrypted_data: bytes) -> bytes:

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(self.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

if __name__ == "__main__":
    util = EncryptionUtil()  

    original_text = "Hello, LU-Connect!"
    encrypted_text = util.encrypt_message(original_text)
    decrypted_text = util.decrypt_message(encrypted_text)

    print("Original Text: ", original_text)
    print("Encrypted Text:", encrypted_text)
    print("Decrypted Text:", decrypted_text)

    sample_bytes = b"Some binary data"
    encrypted_bytes = util.encrypt_data(sample_bytes)
    decrypted_bytes = util.decrypt_data(encrypted_bytes)

    print("\nOriginal Bytes: ", sample_bytes)
    print("Encrypted Bytes:", encrypted_bytes)
    print("Decrypted Bytes:", decrypted_bytes)
