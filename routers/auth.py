from fastapi import APIRouter, Request
from schemas import RegisterData, LoginData

from services.auth_service import create_new_user, login_user, logout_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.get('/register')
async def register_get():
    pass

@router.post("/register")
async def register_post(data: RegisterData):
    return create_new_user(data.model_dump())

@router.get('/login')
async def login_get():
    pass

@router.post("/login")
async def login_post(data: LoginData, request: Request):
    return login_user(data.model_dump(), request)

@router.post("/logout")
async def logout_post(request: Request):
    return logout_user(request)