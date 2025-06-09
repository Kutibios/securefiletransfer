from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def generate_key():
    return get_random_bytes(32)  # AES-256 için 32 byte anahtar

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + ciphertext + tag

def decrypt_data(encrypted_data_with_nonce_tag, key):
    nonce = encrypted_data_with_nonce_tag[:16]
    ciphertext = encrypted_data_with_nonce_tag[16:-16]
    tag = encrypted_data_with_nonce_tag[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

def get_file_hash(data):
    return hashlib.sha256(data).hexdigest().encode('utf-8') # Hash'i byte olarak döndür
