from fastapi import APIRouter, Request, Depends
from sqlalchemy.orm import Session

from main import limiter
from database import get_db
from schemas import RegisterData, LoginData
from services.auth_service import create_new_user, login_user, logout_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register")
@limiter.limit("3/minute")
async def register_post(request: Request, data: RegisterData, db: Session = Depends(get_db)):
    return create_new_user(data.model_dump(), db)

@router.post("/login")
@limiter.limit("5/minute")
async def login_post(request: Request, data: LoginData, db: Session = Depends(get_db)):
    return login_user(data.model_dump(), request, db)

@router.post("/logout")
async def logout_post(request: Request):
    return logout_user(request)