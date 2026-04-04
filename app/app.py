from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from app.auth import create_new_user, login_user, add_new_vault_item

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
async def vault_get():
    pass

@app.post('/vault')
async def vault_post(data: VaultItemData, request: Request):
    return add_new_vault_item(data.dict(), request)
