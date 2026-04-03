from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from db.db import User, VaultItem, session
from sqlalchemy.exc import IntegrityError
from zxcvbn import zxcvbn
from os import urandom
from hashlib import pbkdf2_hmac

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
        return {'status': 'error', 'message': f'Password is too easy, suggestions: {password_strength['feedback']['suggestions']}'}

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
    key = pbkdf2_hmac('sha256', password, kdf_salt, iterations)
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
        return {'status': 'ok', 'message': 'Login successful'}
    except VerifyMismatchError:
        session.commit()
        return {'status': 'error', 'message': 'wrong email or password'}

