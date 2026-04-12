from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from db.db import User, VaultItem, db_session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from zxcvbn import zxcvbn
from os import urandom
from hashlib import pbkdf2_hmac
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

active_key = {}

def hash_password(password):
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    return password_hash

def get_user_email(email):
    return db_session.query(User).filter_by(email=email).first()

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
        db_session.add(new_user)
        db_session.commit()
        return {'status': 'ok', 'message': 'user has been successfuly created'}
    except IntegrityError:
        db_session.rollback()
        return {'status': 'error', 'message': 'error has occured'}

def kdf_hash(password, kdf_salt, iterations=100000):
    key = pbkdf2_hmac('sha256', password.encode(), kdf_salt, iterations)
    return key

def login_user(data, request):
    email = data.get('email')
    password = data.get('password')
    user = get_user_email(email)

    if user is None:
        return {'status': 'error', 'message': 'wrong email or password'}

    ph = PasswordHasher()
    password_hash = user.password_hash
    
    try:
        if ph.verify(password_hash, password):
            request.session['user_id'] = user.id
        master_key = kdf_hash(password, user.kdf_salt)
        active_key[user.id] = master_key
        return {'status': 'ok', 'message': 'Login successful'}
    except VerifyMismatchError:
        db_session.commit()
        return {'status': 'error', 'message': 'wrong email or password'}

def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ['http', 'https']:
        return False, 'invalid scheme'

    if not parsed.netloc:
        return False, 'missing domain'

    return True, None

def encrypt_password(password, master_key):
    iv = urandom(12)
    password = password.encode()
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    password_encrypted = encryptor.update(password) + encryptor.finalize()
    return password_encrypted, iv, encryptor.tag

def decrypt_password(iv, password_encrypted, tag, master_key):
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(password_encrypted) + decryptor.finalize()
    return plain_text

def add_new_vault_item(data, request):
    current_user_id = request.session.get('user_id')
    user_master_key = active_key.get(current_user_id)
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

    if user_master_key is None:
        return {'status': 'error', 'message': 'session has expired. login again'}
    
    password_encrypted, iv, tag = encrypt_password(password, master_key = user_master_key)

    new_vault_item = VaultItem(user_id = current_user_id, title = title, url = url, login = login, password_encrypted = password_encrypted, iv = iv, tag = tag, notes = notes)
    try:
        db_session.add(new_vault_item)
        db_session.commit()
        return {'status': 'ok', 'message': 'service has been added to vault'}
    except IntegrityError:
        db_session.rollback()
        return {'status': 'error', 'message': 'an error has occured'}

def get_vault_items(request):
    current_user_id = request.session.get('user_id')
    user_master_key = active_key.get(current_user_id)
    items_list = []
    
    if user_master_key is None or current_user_id is None:
        return {'status': 'error', 'message': 'session has expired. login again'}

    vault_items = db_session.query(VaultItem).filter_by(user_id = current_user_id)
    
    for vault_item in vault_items:
        item_data = {}
        
        item_data['id'] = vault_item.id
        item_data['title'] = vault_item.title
        item_data['url'] = vault_item.url
        item_data['login'] = vault_item.login

        try:
            plain_password = decrypt_password(vault_item.iv, vault_item.password_encrypted, vault_item.tag, user_master_key).decode('utf-8')
        except InvalidTag:
            plain_password = 'INTEGRITY ERROR'

        item_data['password'] = plain_password
        item_data['updated_at'] = vault_item.updated_at
        item_data['notes'] = vault_item.notes
        
        items_list.append(item_data)

    return items_list

def delete_vault_item(item_id, request):
    current_user_id = request.session.get('user_id')

    if current_user_id is None:
        return {'status': 'error', 'message': 'session has expired. login again'}

    try:
        deleted_count = db_session.query(VaultItem).filter_by(user_id = current_user_id, id = item_id).delete()
        
        if deleted_count == 0:
            return {'status': 'error', 'message': 'no db element found'}

        db_session.commit()

    except SQLAlchemyError:
        db_session.rollback()
        return {'status': 'error', 'message': 'a db error has occured'}

    return {'status': 'ok', 'message': 'item successfully deleted'}

def update_vault_item(item_id, data, request):
    current_user_id = request.session.get('user_id')
    user_master_key = active_key.get(current_user_id)

    if current_user_id is None or user_master_key is None:
        return {'status': 'error', 'message': 'session has expired. login again'}
    
    vault_item = db_session.query(VaultItem).filter_by(user_id=current_user_id, id=item_id).first()
    if not vault_item:
        return {'status': 'error', 'message': 'item not found'}

    new_encrypted_data = None
    if data.get('password'):
        try:
            new_encrypted_data = encrypt_password(data.get('password'), user_master_key)
        except Exception as e:
            return {'status': 'error', 'message': f"encryption failed: {str(e)}"}

    try:
        if data.get('title'):
            vault_item.title = data.get('title')
        
        if data.get('url'):
            is_valid, error = validate_url(data.get('url'))
            if not is_valid:
                return {'status': 'error', 'message': error}    
            vault_item.url = data.get('url')
        
        if data.get('login'):
            vault_item.login = data.get('login')

        if new_encrypted_data:
            vault_item.password_encrypted, vault_item.iv, vault_item.tag = new_encrypted_data
        
        if data.get('notes') is not None:
            vault_item.notes = data.get('notes')

        db_session.commit()

    except SQLAlchemyError:
        db_session.rollback()
        return {'status': 'error', 'message': 'a db error has occured'}

    return {'status': 'ok', 'message': 'item successfully updated'}

def logout_user(request):
    current_user_id = request.session.get('user_id')
    if current_user_id in active_key:
        del active_key[current_user_id]
    request.session.clear()
    return {'status': 'ok', 'message': 'logged out'}