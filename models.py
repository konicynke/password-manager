from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, LargeBinary, DateTime, ForeignKey, func
from datetime import datetime
from typing import List

from database import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    vault_items: Mapped[List["VaultItem"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class VaultItem(Base):
    __tablename__ = "vault_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    user: Mapped["User"] = relationship(back_populates="vault_items")
    
    title: Mapped[str] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(String(255))
    login: Mapped[str] = mapped_column(String(120))
    password_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    iv: Mapped[bytes] = mapped_column(LargeBinary)
    tag: Mapped[bytes] = mapped_column(LargeBinary)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    notes: Mapped[str] = mapped_column(String(500), nullable=True)