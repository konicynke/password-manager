from argon2 import PasswordHasher
from os import urandom
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def hash_password(password):
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    return password_hash

def kdf_hash(password, kdf_salt, iterations=100000):
    key = pbkdf2_hmac('sha256', password.encode(), kdf_salt, iterations)
    return key

def encrypt_password(password, master_key):
    iv = urandom(12)
    password_encoded = password.encode()
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    password_encrypted = encryptor.update(password_encoded) + encryptor.finalize()
    return password_encrypted, iv, encryptor.tag

def decrypt_password(iv, password_encrypted, tag, master_key):
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(password_encrypted) + decryptor.finalize()
    return plain_text