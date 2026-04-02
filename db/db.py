from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import create_engine, String, LargeBinary, DateTime, ForeignKey
from datetime import datetime
from typing import List

engine = create_engine("postgresql+psycopg2://admin:admin@postgres:5433/password_manager")
Session = scoped_session(sessionmaker(bind=engine))
session = Session()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    notes: Mapped[str] = mapped_column(String(500))


if __name__ == '__main__':
    Base.metadata.create_all(engine)