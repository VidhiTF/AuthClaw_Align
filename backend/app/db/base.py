"""Database base configuration"""
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Import models so Alembic can discover them
from app.db.models import *