import os
import sys
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv


def _runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


RUNTIME_DIR = _runtime_dir()
load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)

_default_db = f"sqlite:///{RUNTIME_DIR / 'data' / 'cyberkb.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", _default_db)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from models import Note, Command, Tool, CVE, OsintResult  # noqa: F401
    (RUNTIME_DIR / "data").mkdir(exist_ok=True)
    Base.metadata.create_all(bind=engine)
