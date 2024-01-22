import datetime
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile,Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.security import OAuth2PasswordRequestForm
from databases import Database
from datetime import timedelta
from typing import List
from sqlalchemy.orm import Session, joinedload
import methods
from schemas import User, ResumeData, get_db, SessionLocal, PasswordReset
from models import UserResponse, UserCreate, Token, TokenData, UserFiles
from constants import DATABASE_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from methods import get_password_hash, verify_password, create_access_token, get_current_user, oauth2_scheme, \
    get_user_from_token, update_user_password
from sqlalchemy import update
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates


# Initialize FastAPI and database
app = FastAPI(
    docs_url="/docs",
    openapi_url='/openapi.json'
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

database = Database(DATABASE_URL)

@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# @app.get("/")
# def index():
#     return {'status': 'Success'}

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
    name="index.html", request=request)


# Routes
@app.post("/register")
async def register_user(user: UserCreate):
    async with database.transaction():
        # Check if the email is already registered
        query = User.__table__.select().where(User.email == user.email)
        existing_user = await database.fetch_one(query)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create a new user
        db_user = await database.execute(User.__table__.insert().values(
            username=user.username,
            email=user.email,
            hashed_password=get_password_hash(user.password),
            role=user.role
        ))

        inserted_user = await database.fetch_one(User.__table__.select().where(User.id == db_user))

        return {
            "id": inserted_user["id"],
            "username": inserted_user["username"],
            "email": inserted_user["email"],
            "role": inserted_user["role"],
            "created_datetime": inserted_user["created_datetime"],
        }


@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Authenticate user using email
    query = User.__table__.select().where(User.email == form_data.username)
    user = await database.fetch_one(query)

    if user is None or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user["role"] != "user":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Insufficient privileges",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
        )

    query = update(User.__table__).where(User.email == form_data.username).values(token=access_token)
    await database.execute(query)

    return {"access_token": access_token, "token_type": "bearer"}


@app.put("/update-password")
async def update_password(
        current_password: str,
        new_password: str,
        confirm_new_password: str,
        token: str = Depends(oauth2_scheme)
):
    # Verify token and get user from the database
    user = get_user_from_token(token)

    # Check if the current password provided matches the user's actual password
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Check if the new password and confirmation match
    if new_password != confirm_new_password:
        raise HTTPException(status_code=400, detail="New password and confirmation do not match")

    # Update the user's password in the database
    update_user_password(user.id, new_password)

    return {"message": "Password updated successfully"}


@app.post("/process-resume/")
async def process_resume(

        pdf_files: List[UploadFile] = File(...),
        token: str = Depends(oauth2_scheme),
):
    db = SessionLocal()
    user = get_user_from_token(token)

    result, csv_path, xml_path = await methods.parse_resume(pdf_files)
    with open(csv_path, 'rb') as file:
        csv_content = file.read()
    with open(xml_path, 'rb') as file:
        xml_content = file.read()

    new_resume_data = ResumeData(
        user_id=user.id,
        extracted_data=result,
        csv_file=csv_content,
        xml_file=xml_content,
    )
    db.add(new_resume_data)
    db.commit()
    db.refresh(new_resume_data)

    return {
        "id": new_resume_data.id,
        "user_id": new_resume_data.user_id,
        "extracted_data": result,
        "csv_file": csv_content,
        "xml_file": xml_content,
        "datetime": datetime.datetime.utcnow()
    }


@app.get('/user-profile')
async def user_profile(token: str = Depends(oauth2_scheme)):
    db = SessionLocal()
    # Ensure that the user and related resume_data are loaded in the same session
    user = db.query(User).options(joinedload(User.resume_data)).filter_by(token=token).first()

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "token": user.token,
        "resume_data": user.resume_data
    }



# Protected route accessible only to users with the "admin" role
@app.get("/admin/users", response_model=List[UserResponse])
async def get_all_users(current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    query = User.__table__.select()
    users = await database.fetch_all(query)
    return users


@app.post("/admin/add-user", response_model=dict)
async def admin_add_user(user: UserCreate, current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    else:
        print(current_user.role)
        async with database.transaction():
            # Check if the email is already registered
            query = User.__table__.select().where(User.email == user.email)
            existing_user = await database.fetch_one(query)
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already registered")

            # Create a new user
            db_user = await database.execute(User.__table__.insert().values(
                username=user.username,
                email=user.email,
                hashed_password=get_password_hash(user.password),
                role=user.role
            ))

            return {
                    "message": "User registered successfully",
                    "id": db_user,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role
                    }


@app.delete("/admin/delete-user/{user_id}", response_model=dict)
async def admin_delete_user(
    user_id: int,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Endpoint to allow an admin to delete a user.
    """
    # Check if the current user is an admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Check if the user to be deleted exists
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete the associated records in the ResumeData table
    db.query(ResumeData).filter(ResumeData.user_id == user_id).delete()

    # Delete the user
    db.delete(user_to_delete)
    db.commit()

    return {"message": "User deleted successfully", "user_id": user_id}


@app.post("/admin/login", response_model=Token)
async def login_for_admin(form_data: OAuth2PasswordRequestForm = Depends()):
    # Authenticate user using email

    query = User.__table__.select().where(User.email == form_data.username)
    user = await database.fetch_one(query)
    print(user)
    if user is None or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    elif user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Insufficient privileges",
            headers={"WWW-Authenticate": "Bearer"},
        )

    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires
        )

        query = update(User.__table__).where(User.email == form_data.username).values(token=access_token)
        await database.execute(query)

        return {"access_token": access_token, "token_type": "bearer"}


@app.get("/admin/user-files/{user_id}", response_model=dict)
async def get_user_files_api(user_id: int, current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Retrieve CSV files for the user
    csv_files = methods.get_user_files(user_id=user_id)

    response_data = {
        "user_id": user_id,
        "csv_files": csv_files
        # Add other fields as needed
    }

    return response_data


@app.get('/admin/view-user/{user_id}')
async def user_profile(user_id: int, current_user: TokenData = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    db = SessionLocal()
    # Ensure that the user and related resume_data are loaded in the same session
    user = db.query(User).options(joinedload(User.resume_data)).filter_by(id=user_id).first()

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "token": user.token,
        "resume_data": user.resume_data
    }


# Endpoint to initiate the forgot password process
@app.post("/forgot-password")
async def forgot_password(email: str, message: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        # Generate a password reset token and store it in the database
        reset_token = PasswordReset(user_id=user.id)
        db.add(reset_token)
        db.commit()
        print("user detected")
        # Send an email with the reset token
        methods.send_password_reset_email(email, message, reset_token.token)

        return {
            "reset_token": reset_token.token,
            "message": "Password reset instructions sent to your email"
        }

    raise HTTPException(status_code=404, detail="User not found")


# Endpoint to reset the password based on the provided token
@app.post("/reset-password")
async def reset_password(token, new_password, db: Session = Depends(get_db)):
    reset_token = db.query(PasswordReset).filter(PasswordReset.token == token).first()
    if reset_token:
        # Reset the user's password
        user = reset_token.user
        user.hashed_password = get_password_hash(new_password)

        # Remove the reset token from the database
        db.delete(reset_token)
        db.commit()
        return {
            "message": "Password reset successfully"
        }

    # raise HTTPException(status_code=404, detail="Invalid token")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)


