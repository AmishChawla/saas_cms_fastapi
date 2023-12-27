import os
import tempfile
from fastapi import HTTPException, Depends, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, List
from constants import SECRET_KEY,ALGORITHM
from models import TokenData
from resume_parser import extract_data

from schemas import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
def get_password_hash(password):
    return pwd_context.hash(password)


# Dependency to verify the password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict,  expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
    return token_data


def get_user_from_token(token: str):
    db = SessionLocal()
    user = db.query(User).filter(User.token == token).first()
    db.close()
    return user


def update_user_password(user_id: int, new_password):
    db = SessionLocal()
    hashed_password = pwd_context.hash(new_password)

    # Update the user's hashed password in the database
    db.execute(
        User.__table__.update().
            where(User.id == user_id).
            values(hashed_password=hashed_password)
    )
    # Commit the changes to the database
    db.commit()


async def parse_resume(files: List[UploadFile] = File(...)):
    try:
        # Temporary directory to save uploaded files
        temp_dir = tempfile.mkdtemp()

        # Save each uploaded file to the temporary directory
        file_paths = []
        for file in files:
            file_path = os.path.join(temp_dir, file.filename)
            with open(file_path, "wb") as file_obj:
                file_obj.write(file.file.read())
            file_paths.append(file_path)

        # Call your resume parser function
        resume_data, csvfile_path, xmlfile_path =await extract_data(file_paths)

        return resume_data, csvfile_path, xmlfile_path

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error processing files: {str(e)}")
    finally:
        # Clean up: Remove the temporary directory and its contents
        for file_path in file_paths:
            os.remove(file_path)
        os.rmdir(temp_dir)