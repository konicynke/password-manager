from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from database import engine, Base
from routers import auth, vault

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Password Manager API")

app.add_middleware(SessionMiddleware, secret_key='password-manager-secret-key')

@app.get('/')
async def get_root():
    return {'status': 'ok', 'message': 'root page is here'}

app.include_router(auth.router)
app.include_router(vault.router)