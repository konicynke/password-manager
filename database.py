from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, DeclarativeBase
import os

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://admin:admin@db:5432/password_manager")

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()