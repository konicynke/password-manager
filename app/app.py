from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import Optional
from app.auth import create_new_user, login_user, add_new_vault_item, get_vault_items, update_vault_item, delete_vault_item, logout_user

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key='password-manager-secret-key')

class RegisterData(BaseModel):
    email: str
    password: str


class LoginData(RegisterData):
    pass


class VaultItemData(BaseModel):
    title: str
    url: str
    login: str
    password: str
    notes: str


class VaultItemUpdate(BaseModel):
    title: Optional[str] = None
    url: Optional[str] = None
    login: Optional[str] = None
    password: Optional[str] = None
    notes: Optional[str] = None

    
@app.get('/')
async def get_root():
    return {'status': 'ok', 'message': 'root page is here'}

@app.get('/register')
async def register_get():
    pass
    
@app.post('/register')
async def register_post(data: RegisterData):
    return create_new_user(data.dict())

@app.get('/login')
async def login_get():
    pass

@app.post('/login')
async def login_post(data: LoginData, request: Request):
    return login_user(data.dict(), request)

@app.get('/vault')
async def vault_get(request: Request):
    return get_vault_items(request)

@app.post('/vault')
async def vault_post(data: VaultItemData, request: Request):
    return add_new_vault_item(data.dict(), request)

@app.delete('/vault/{item_id}')
async def vault_delete(item_id: int, request: Request):
    return delete_vault_item(item_id, request)

@app.patch('/vault/{item_id}')
async def vault_patch(item_id: int, data: VaultItemUpdate, request: Request):
    return update_vault_item(item_id, data.dict(), request)

@app.post('/logout')
async def logout_post(request: Request):
    return logout_user(request)