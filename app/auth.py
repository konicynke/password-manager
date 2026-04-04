from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from db.db import User, VaultItem, session
from sqlalchemy.exc import IntegrityError
from zxcvbn import zxcvbn
from os import urandom
from hashlib import pbkdf2_hmac
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

active_key = {}

def hash_password(password):
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    return password_hash

def get_user_email(email):
    return session.query(User).filter_by(email=email).first()

def create_new_user(data):
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return {'status': 'error', 'message': 'missing fields'}

    if get_user_email(email):
        return {'status': 'error', 'message': 'email already in use'}

    password_strength = zxcvbn(password)
    if password_strength['score'] <= 2:
        return {'status': 'error', 'message': f"Password is too easy, suggestions: {password_strength['feedback']['suggestions']}"}

    password_hash = hash_password(password)
    kdf_salt = urandom(16)

    new_user = User(email = email, password_hash = password_hash, kdf_salt = kdf_salt)
    try:
        session.add(new_user)
        session.commit()
        return {'status': 'ok', 'message': 'user has been successfuly created'}
    except IntegrityError:
        session.rollback()
        return {'status': 'error', 'message': 'error has occured'}

def kdf_hash(password, kdf_salt, iterations=100000):
    key = pbkdf2_hmac('sha256', password.encode(), kdf_salt, iterations)
    return key

def login_user(data):
    email = data.get('email')
    password = data.get('password')
    user = get_user_email(email)

    if user is None:
        return {'status': 'error', 'message': 'wrong email or password'}

    ph = PasswordHasher()
    password_hash = user.password_hash
    
    try:
        ph.verify(password_hash, password)
        session.commit()
        session['user_id'] = user.id
        master_key = kdf_hash(password, user.kdf_salt)
        active_key.update({'master_key': master_key})
        return {'status': 'ok', 'message': 'Login successful'}
    except VerifyMismatchError:
        session.commit()
        return {'status': 'error', 'message': 'wrong email or password'}

def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ['http', 'https']:
        return False, 'invalid scheme'

    if not parsed.netloc:
        return False, 'missing domain'

    return True, None

def encrypt_password(password, iv, master_key):
    password = password.encode()
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(password) + encryptor.finalize()
    return ct, encryptor.tag

def decrypt_password(iv, ct, tag, master_key):
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ct) + decryptor.finalize()
    return plain_text

def add_new_vault_item(data):
    current_user_id = session.get('user_id')
    title = data.get('title')
    url = data.get('url')
    login = data.get('login')
    password = data.get('password')
    notes = data.get('notes')

    required_fields = ['title', 'url', 'login', 'password']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return {'status': 'error', 'message': f"Missing fields: {', '.join(missing_fields)}"}
    
    is_valid, error = validate_url(url)
    if not is_valid:
        return {'status': 'error', 'message': error}
    
    iv = urandom(16)

    password_encrypted = encrypt_password(password, iv, master_key=active_key['master_key'])

    new_vault_item = VaultItem(user_id = current_user_id, title = title, url = url, login = login, password_encrypted = password_encrypted, iv = iv, notes = notes)
    try:
        session.add(new_vault_item)
        session.commit()
        return {'status': 'ok', 'message': 'service has been added to vault'}
    except IntegrityError:
        session.rollback()
        return {'status': 'error', 'message': 'an error has occured'}

def logout_user():
    active_key.clear()
    pass

if __name__ == '__main__':
    master_key = '12345678901234567890123456789012'
    master_key = master_key.encode()
    iv = urandom(12)
    password = '123456789012345'
    ct, tag = encrypt_password(password, iv, master_key)
    print(tag, ct)
    plain_text = decrypt_password(iv, ct, tag, master_key)
    print(f'\n{plain_text}')