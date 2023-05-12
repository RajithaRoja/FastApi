from database import Base
from sqlalchemy import Column, Integer, String


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    register_number = Column(Integer, default=None)
    first_name = Column(String, default=None)
    last_name = Column(String, default=None)
    username = Column(String, default=None)
    email = Column(String, default=None)
    gender = Column(String, default=None)
    phone_number = Column(String, default=None)
    hashed_password = Column(String, default=None)
