from typing_extensions import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, EmailStr, constr
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
    username: str = Field(min_length=3)
    email: EmailStr
    gender: constr(strip_whitespace=True, regex='^(male|female|others)$')
    phone_number: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class passwordupdate(BaseModel):
    old_password: str = Field(..., alias="oldPassword")
    new_password: str = Field(..., alias="newPassword")
    confirm_password: str = Field(..., alias="confirmPassword")


class PasswordUpdate(BaseModel):
    username_or_email: str = Field(..., alias="username")
    new_password: str = Field(..., alias="newPassword")
    confirm_password: str = Field(..., alias="confirmPassword")


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


# Creating access token
@router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    # Fixed argument order
    token = create_access_token(user.id, user.username, timedelta(minutes=20))
    return {'access_token': token, 'token_type': 'bearer'}


# Route handler function to update user's password
@router.put("/forget_password", status_code=status.HTTP_200_OK)
async def password_update(
    password_update_request: PasswordUpdate,
    db: Session = Depends(get_db)
):
    user = db.query(Users).filter(
        (Users.username == password_update_request.username_or_email) | (Users.email == password_update_request.username_or_email)
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    if password_update_request.new_password != password_update_request.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='New password and confirm password do not match')
    new_hashed_password = bcrypt_context.hash(password_update_request.new_password)
    db.query(Users).filter(
        (Users.username == password_update_request.username_or_email) | (Users.email == password_update_request.username_or_email)
    ).update({Users.hashed_password: new_hashed_password})
    db.commit()

    return {"message": "Password changed successfully"}


@router.put("/reset_password")
async def reset_password(password_update: passwordupdate,
                         current_user: dict = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.id == current_user['id']).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_password = password_update.old_password
    new_password = password_update.new_password
    confirm_password = password_update.confirm_password

    if not bcrypt_context.verify(old_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password")

    if new_password != confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password and confirm password do not match")

    hashed_password = bcrypt_context.hash(new_password)
    user.hashed_password = hashed_password
    db.commit()

    return {"message": "Password updated successfully"}


@router.get("/users", status_code=status.HTTP_200_OK)
async def get_users(db: db_dependency, current_user: dict = Depends(get_current_user)):
    # Check if the current user is authenticated
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    # Check if the current user has the necessary permissions (if applicable)
    # Add your permission logic here
    
    # Retrieve all users from the database
    users = db.query(Users).all()
    
    # Return the users as the response
    return users
