import datetime
import io
import json
import tempfile

from pdfminer.high_level import extract_text
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Path, Body
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
from schemas import User, ResumeData, get_db, SessionLocal, PasswordReset, PDFFiles, Tenant
from models import UserResponse, UserCreate, Token, TokenData, UserFiles, AdminInfo, Company
from constants import DATABASE_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from methods import get_password_hash, verify_password, create_access_token, get_current_user, oauth2_scheme, \
    get_user_from_token, update_user_password
from sqlalchemy import update
from fastapi.responses import HTMLResponse, FileResponse
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
@app.post("/register/{company_name}")
async def register_user(user: UserCreate, company_name: str = Path(...), company_id: int = Body(...)):
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
            role=user.role,
            status="active",
            created_datetime=datetime.datetime.utcnow(),
            company_id=company_id

        ))

        inserted_user = await database.fetch_one(User.__table__.select().where(User.id == db_user))

        return {
            "id": inserted_user["id"],
            "username": inserted_user["username"],
            "email": inserted_user["email"],
            "role": inserted_user["role"],
            "created_datetime": inserted_user["created_datetime"],
            "status": inserted_user["status"],
            "company_id": inserted_user["company_id"],
            "company_name": company_name
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

    pdf_resumes_content = []
    # for pdf_file in pdf_files:
    #     try:
    #         with tempfile.NamedTemporaryFile(delete=False) as temp_file:
    #             temp_file.write(pdf_file.file.read())
    #             temp_file_path = temp_file.name
    #
    #         content = extract_text(temp_file_path)
    #         # pdf_content = pdf_file.file.read()
    #         pdf_file.file.seek(0)
    #         #
    #         # # pdf_bytes_io = io.BytesIO(pdf_content)
    #         # # pdf_content = pdf_bytes_io.read()
    #         # # pdf_result = methods.extract_text_from_pdf(pdf_content)
    #
    #         print(f"PDF Content Size: {len(content)}")
    #         pdf_resumes_content.append(content)
    #     except Exception as e:
    #         print(f"Error reading PDF file: {e}")

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
        "datetime": datetime.datetime.utcnow(),
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
        "resume_data": user.resume_data,
        "status": user.status
    }


# Protected route accessible only to users with the "admin" role
@app.get("/admin/users", response_model=List[UserResponse])
async def get_all_users(token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    query = User.__table__.select().where(User.company_id == current_user.company_id)
    # where(User.email == user.email)
    users = await database.fetch_all(query)
    return users


@app.post("/admin/add-user", response_model=dict)
async def admin_add_user(user: UserCreate, token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
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
                role=user.role,
                status="active",
                company_id=current_user.company_id
            ))

            return {
                "message": "User registered successfully",
                "id": db_user,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "company_id": current_user.company_id
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
        "status": user.status,
        "resume_data": user.resume_data
    }


# Endpoint to initiate the forgot password process
@app.post("/forgot-password")
async def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        # Generate a password reset token and store it in the database
        reset_token = PasswordReset(user_id=user.id)
        db.add(reset_token)
        db.commit()
        print("user detected")
        # Send an email with the reset token
        methods.send_password_reset_email(email, reset_token.token)

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

    # Endpoint to retrieve the list of uploaded PDFs
    # @app.get("/my-pdfs")
    # async def get_my_pdfs(
    #         current_user: User = Depends(get_db)
    # ):
    #     # Retrieve the list of PDFs for the current user
    #     return current_user.pdf_files
    #
    # # Endpoint to serve a specific PDF file
    # @app.get("/pdf/{id}/")
    # async def get_pdf(id: int, current_user: User = Depends(get_db)):
    #     # Check if the requested PDF file exists for the current user
    #     pdf_file_db = current_user.db.query(PDFFiles).filter_by(id=id, user_id=current_user.id).first()
    #     if pdf_file_db:
    #         return FileResponse(io.BytesIO(pdf_file_db.file_content), media_type="application/pdf")
    #     else:
    #         raise HTTPException(status_code=404, detail="File not found")
    #
    # # raise HTTPException(status_code=404, detail="Invalid token")


@app.put("/admin/edit-user")
async def edit_user(
        user_id: int,
        username: str,
        role: str,
        status: str,
        token: str = Depends(oauth2_scheme)
):
    # Verify token and get user from the database
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    query = update(User.__table__).where(User.id == user_id).values(username=username, role=role, status=status)
    await database.execute(query)

    return {
        "message": "User updated successfully"
    }


@app.post("/register-admin")
async def register_admin(admin: AdminInfo):
    async with database.transaction():
        # Check if the email is already registered
        query = User.__table__.select().where(User.email == admin.email)
        existing_user = await database.fetch_one(query)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create a new user
        db_user = await database.execute(User.__table__.insert().values(
            username=admin.username,
            email=admin.email,
            hashed_password=get_password_hash(admin.password),
            role=admin.role,
            status="active",
            created_datetime=datetime.datetime.utcnow()
        ))

        inserted_user = await database.fetch_one(User.__table__.select().where(User.id == db_user))

        return {
            "id": inserted_user["id"],
            "username": inserted_user["username"],
            "email": inserted_user["email"],
            "role": inserted_user["role"],
            "created_datetime": inserted_user["created_datetime"],
            "status": inserted_user["status"],
        }


@app.post("/register-company")
async def register_company(company: Company, token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    async with database.transaction():
        # Check if the email is already registered
        query = Tenant.__table__.select().where(Tenant.email == company.email)
        existing_company = await database.fetch_one(query)
        if existing_company:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Create a new user
        db_user = await database.execute(Tenant.__table__.insert().values(
            name=company.name,
            email=company.email,
            phone_no=company.phone_no,
            address=company.address,
            description=company.description,
            admin_id=current_user.id,
            status="active"
        ))

        inserted_user = await database.fetch_one(Tenant.__table__.select().where(Tenant.id == db_user))
        print(current_user.company_id, current_user.status, current_user.email)
        print(inserted_user["id"])
        current_user.company_id = inserted_user["id"]
        print(current_user.company_id, current_user.status, current_user.email)
        query = update(User.__table__).where(User.id == current_user.id).values(company_id=inserted_user["id"])
        await database.execute(query)
        print(current_user.id, current_user.company_id, current_user.status, current_user.email)
        return {
            "id": inserted_user["id"],
            "name": inserted_user["name"],
            "email": inserted_user["email"],
            "phone_no": inserted_user["phone_no"],
            "address": inserted_user["address"],
            "description": inserted_user["description"],
            "created_datetime": inserted_user["created_datetime"],
            "status": inserted_user["status"],
            "admin_id": inserted_user["admin_id"],
        }


@app.get("/companies")
async def get_all_users():
    query = Tenant.__table__.select()
    tenants = await database.fetch_all(query)
    return tenants


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
