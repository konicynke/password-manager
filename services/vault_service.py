from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from cryptography.exceptions import InvalidTag
from urllib.parse import urlparse
from zxcvbn import zxcvbn

from database import SessionLocal
from models import VaultItem
from services.crypto import encrypt_password, decrypt_password
from services.auth_service import active_key

db_session = SessionLocal()

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return False, 'invalid scheme'
    if not parsed.netloc:
        return False, 'missing domain'
    return True, None

def add_new_vault_item(data, request):
    current_user_id = request.session.get('user_id')
    user_master_key = active_key.get(current_user_id)

    if user_master_key is None or current_user_id is None:
        return {'status': 'error', 'message': 'session has expired. login again'}

    title = data.get('title')
    url = data.get('url')
    login = data.get('login')
    password = data.get('password')
    notes = data.get('notes')
    
    is_valid, error = validate_url(url)
    if not is_valid:
        return {'status': 'error', 'message': error}

    password_encrypted, iv, tag = encrypt_password(password, user_master_key)

    new_vault_item = VaultItem(
        user_id=current_user_id, title=title, url=url, login=login, 
        password_encrypted=password_encrypted, iv=iv, tag=tag, notes=notes
    )
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

    vault_items = db_session.query(VaultItem).filter_by(user_id=current_user_id).all()
    
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
        deleted_count = db_session.query(VaultItem).filter_by(user_id=current_user_id, id=item_id).delete()
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

def audit_passwords(request):
    current_user_id = request.session.get('user_id')
    user_master_key = active_key.get(current_user_id)

    if current_user_id is None or user_master_key is None:
        return {'status': 'error', 'message': 'session has expired. login again'}

    vault_items = get_vault_items(request)
    
    if isinstance(vault_items, dict) and vault_items.get('status') == 'error':
        return vault_items

    password_usage_count = {}

    for item in vault_items:
        pwd = item['password']
        if pwd not in password_usage_count:
            password_usage_count[pwd] = []
        password_usage_count[pwd].append(item['title'])

    for item in vault_items:
        others = [t for t in password_usage_count[item['password']] if t != item['title']]
        item['reused_in'] = others
        item['score'] = zxcvbn(item['password'])['score']
        
    return vault_items