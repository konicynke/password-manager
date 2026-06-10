from pydantic import BaseModel, EmailStr
from typing import Optional

class RegisterData(BaseModel):
    email: EmailStr
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