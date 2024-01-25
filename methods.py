import os
import tempfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP_SSL, SMTP
from fastapi import HTTPException, Depends, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, List
from passlib.context import CryptContext


from sqlalchemy import select
from starlette.responses import JSONResponse

from constants import SECRET_KEY, ALGORITHM, EMAIL, EMAIL_PASSWORD
from sqlalchemy.orm import Session

from models import TokenData, UserFiles
from resume_parser import extract_data

from schemas import User, get_db, SessionLocal, ResumeData, PasswordReset, PDFFiles
from sqlalchemy.orm import class_mapper

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



def get_password_hash(password):
    return pwd_context.hash(password)


# Dependency to verify the password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
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
    hashed_password = pwd_context.hash(new_password)
    db = SessionLocal()

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
                print(f"parsersume {file.file}")
                file_obj.write(file.file.read())
            file_paths.append(file_path)

        # Call your resume parser function
        resume_data, csvfile_path, xmlfile_path = await extract_data(file_paths)
        print(resume_data, csvfile_path, xmlfile_path)
        return resume_data, csvfile_path, xmlfile_path

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error processing files: {str(e)}")
    finally:
        # Clean up: Remove the temporary directory and its contents
        for file_path in file_paths:
            os.remove(file_path)
        os.rmdir(temp_dir)


def row_to_dict(row):
    data = {}
    for column in class_mapper(row.__class__).mapped_table.c:
        data[column.name] = getattr(row, column.name)
    return data


def get_user_files(user_id: int):
    db = SessionLocal()
    user_csv_files = db.query(ResumeData.csv_file).filter(ResumeData.user_id == user_id).filter(ResumeData.csv_file.isnot(None)).all()

    # Extract CSV file paths from the result
    csv_files = [str(file) for file in user_csv_files]

    return csv_files

def create_password_reset_token(email: str, expires_delta: timedelta):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if user:
        db_password_reset = PasswordReset(user_id=user.id)
        db.add(db_password_reset)
        db.commit()
        db.refresh(db_password_reset)

        token_data = {
            "sub": str(db_password_reset.id),
            "email": email,
        }
        access_token_expires = timedelta(minutes=expires_delta)
        access_token = create_access_token(
            data={"sub": str(db_password_reset.id), "email": email},
            expires_delta=access_token_expires,
        )
        return access_token


def send_password_reset_email(email: str, token):
    print(f"tryng to send email")

    message = f"""<p>Click the following link to reset your password: <a href='https://resume-parser-flask.onrender.com/reset-password/{token}'>Reset Password</a></p> """

    try:
        # msg = MIMEMultipart()
        msg = MIMEText(message, "html")

        msg['Subject'] = "Password Reset"
        msg['From'] = "noreply"
        msg['To'] = email
        port = 587  # For STARTTLS

        # Connect to the email server and start TLS
        server = SMTP("smtp.gmail.com", port)
        server.starttls()
        # Login to the email server
        server.login("codester641@gmail.com","islv fkwf yqar yiad")
        # msg.set_type("multipart/mixed")

        # Send the email
        server.sendmail("codester641@gmail.com", email, msg.as_string())
        server.quit()
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not send password reset email",
        )

