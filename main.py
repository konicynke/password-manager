from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

from extensions import limiter
from database import engine, Base
from routers import auth, vault

Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Password Manager API")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

secret_key = os.getenv("SECRET_KEY")

if secret_key is None:
    raise RuntimeError("SECRET_KEY is not set")

app.add_middleware(SessionMiddleware, secret_key=secret_key)
app.add_middleware(
CORSMiddleware,
  allow_origins=["http://localhost:5173"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)

@app.get('/')
async def get_root():
    return {'status': 'ok', 'message': 'root page is here'}

app.include_router(auth.router)
app.include_router(vault.router)