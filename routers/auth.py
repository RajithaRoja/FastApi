from typing_extensions import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, EmailStr, Form
from models import Users
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from database import SessionLocal
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import timedelta, datetime


router = APIRouter()


SECRET_KEY = 'RAJITHAROSE'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')


class CreateUserRequest(BaseModel):
    register_number: int
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    gender: str
    phone_number: int
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str
        

class UserCredentials(BaseModel):
    username: str
    password: str
        
        
class ChangePassword(BaseModel):
    username_or_email: str = Form(...)
    new_password: str = Form(...)
    confirm_password: str = Form(...)


# Dependency to get a database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


# Authenticate username or email and Password
def authenticate_user(username_or_email: str, password: str, db):
    user = db.query(Users).filter(Users.username == username_or_email).first()
    if not user:
        user = db.query(Users).filter(Users.email == username_or_email).first()
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect username or email")
    if not bcrypt_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    return user


# Creating Access token
def create_access_token(user_id: int, username: str, expires_delta: timedelta):
    payload = {'sub': username, 'id': user_id, 'exp': datetime.utcnow() + expires_delta}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')


# Create New Student Register
@router.post("/auth", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency,
                      create_user_request: CreateUserRequest):
    existing_user = db.query(Users).filter(
        (Users.email == create_user_request.email) |
        (Users.username == create_user_request.username) |
        (Users.register_number == create_user_request.register_number)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with the provided email, username or register number already exists"
        )
    create_user_model = Users(
        register_number=create_user_request.register_number,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        username=create_user_request.username,
        email=create_user_request.email,
        gender=create_user_request.gender,
        phone_number=create_user_request.phone_number,
        hashed_password=bcrypt_context.hash(create_user_request.password)
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token")
async def login_for_access_token(
    credentials: UserCredentials,
    db: Session = Depends(get_db)
):
    # Extract username_or_email and password from the credentials
    username_or_email = credentials.username
    password = credentials.password

    # Find user by username or email in the database
    user = db.query(Users).filter(
        (Users.username == username_or_email) |
        (Users.email == username_or_email)
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Authenticate the user
    if not authenticate_user(username_or_email, password, db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Generate the access token
    token = create_access_token(user.id, user.username, timedelta(minutes=20))
    return {'access_token': token, 'token_type': 'bearer'}


@app.put('/change_user_password')
async def change_user_password(change_password: ChangePassword, db: db_dependency):
    user = db.query(UserInput).filter((UserInput.email == change_password.username_or_email) |
                                      (UserInput.username == change_password.username_or_email)).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    if change_password.new_password != change_password.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password should be same")
    new_password_hashed = bcrypt_context.hash(change_password.new_password)
    user.password = new_password_hashed
    db.commit()
    return {'message': 'Password changed successfully'}


@router.get("/users", status_code=status.HTTP_200_OK)
async def get_users(db: Session = Depends(get_db)):
    # Fetch all users from the database
    users = db.query(Users).all()
    return users
