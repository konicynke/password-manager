from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.exc import IntegrityError
from zxcvbn import zxcvbn
from os import urandom

from database import SessionLocal
from models import User
from services.crypto import hash_password, kdf_hash

db_session = SessionLocal()
active_key = {}

def get_user_email(email):
    return db_session.query(User).filter_by(email=email).first()

def create_new_user(data):
    email = data.get('email')
    password = data.get('password')

    if get_user_email(email):
        return {'status': 'error', 'message': 'email already in use'}

    password_strength = zxcvbn(password)
    if password_strength['score'] <= 2:
        return {'status': 'error', 'message': f"Password is too easy, suggestions: {password_strength['feedback']['suggestions']}"}

    password_hash = hash_password(password)
    kdf_salt = urandom(16)

    new_user = User(email=email, password_hash=password_hash, kdf_salt=kdf_salt)
    try:
        db_session.add(new_user)
        db_session.commit()
        return {'status': 'ok', 'message': 'user has been successfuly created'}
    except IntegrityError:
        db_session.rollback()
        return {'status': 'error', 'message': 'error has occured'}

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
        return {'status': 'error', 'message': 'wrong email or password'}

def logout_user(request):
    current_user_id = request.session.get('user_id')
    if current_user_id in active_key:
        del active_key[current_user_id]
    request.session.clear()
    return {'status': 'ok', 'message': 'logged out'}