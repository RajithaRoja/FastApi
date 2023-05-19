from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = 'postgresql://student_register_slk3_user:VaaxHmrePM0FJqAcsQ4eAicHhW4Ccq2a@dpg-chjg20qk728k56jda580-a/student_register_slk3'

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
