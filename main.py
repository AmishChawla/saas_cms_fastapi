import datetime
import io
import json
import math
import tempfile
from pdfminer.high_level import extract_text
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Path, Body, Query, Form
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import IntegrityError

from databases import Database
from datetime import timedelta
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload, selectinload
import methods
import models
from schemas import User, ResumeData, get_db, SessionLocal, PasswordReset, PDFFiles, Service, UserServices, Company
from models import UserResponse, UserCreate, Token, TokenData, UserFiles, AdminInfo, UsersResponse, UserCompanyResponse
from constants import DATABASE_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from methods import get_password_hash, verify_password, create_access_token, get_current_user, oauth2_scheme, \
    get_user_from_token, update_user_password
from sqlalchemy import update, select, func
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

# Initialize FastAPI and database
app = FastAPI(
    docs_url="/docs",
    openapi_url='/openapi.json',
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
@app.post("/api/register")
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
            role=user.role,
            status="active",
            created_datetime=datetime.datetime.utcnow(),

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


@app.post("/api/login", response_model=dict)
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
    elif user["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is blocked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user["status"] == "deleted":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires
        )

        # Fetch user services
        user_services_query = """
            SELECT s.*
            FROM services s
            INNER JOIN user_services us ON s.service_id = us.service_id
            WHERE us.user_id = :user_id
        """
        user_services = await database.fetch_all(user_services_query, values={"user_id": user.id})

        # Fetch company details
        company_query = """
            SELECT c.*
            FROM companies c
            WHERE c.user_id = :user_id
        """
        company = await database.fetch_one(company_query, values={"user_id": user.id})

        # Update user token
        query = update(User.__table__).where(User.email == form_data.username).values(token=access_token)
        await database.execute(query)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "email": user.email,
            "services": [{"id": service["service_id"], "name": service["name"]} for service in user_services],
            "company": {"id": company["id"], "name": company["name"]} if company else None
        }


@app.put("/api/update-password")
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


@app.post("/api/process-resume/")
async def process_resume(

        pdf_files: List[UploadFile] = File(...),
        token: str = Depends(oauth2_scheme),
):
    db = SessionLocal()
    user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=user.id, service_name="resume_parser"):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

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


@app.get('/api/user-profile')
async def user_profile(token: str = Depends(oauth2_scheme)):
    db = SessionLocal()
    # Ensure that the user and related resume_data are loaded in the same session
    user = db.query(User).options(joinedload(User.resume_data)).filter_by(token=token).first()

    # Fetch user services
    user_services_query = """
        SELECT s.*
        FROM services s
        INNER JOIN user_services us ON s.service_id = us.service_id
        WHERE us.user_id = :user_id
    """
    user_services = await database.fetch_all(user_services_query, values={"user_id": user.id})

    # Fetch company details
    company_query = """
        SELECT c.*
        FROM companies c
        WHERE c.user_id = :user_id
    """
    company = await database.fetch_one(company_query, values={"user_id": user.id})

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "profile_picture": user.profile_picture,
        "token": user.token,
        "resume_data": user.resume_data,
        "status": user.status,
        "services": [{"id": service["service_id"], "name": service["name"]} for service in user_services],
        "company": {"id": company["id"], "name": company["name"]} if company else None
    }


@app.get("/api/admin/users")
async def get_all_users(
        token: str = Depends(oauth2_scheme),
):
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Build the query to fetch users and their associated companies
    db = SessionLocal()
    users_with_company = (
        db.query(User)
        .outerjoin(Company, User.id == Company.user_id)
        .options(joinedload(User.company))
        .filter(User.status != "deleted")  # Exclude users with status "deleted"
        .all()
    )
    return users_with_company


################################# GET ALL DELETED USERS #########################
@app.get("/api/admin/deleted-users")
async def get_all_deleted_users(
        token: str = Depends(oauth2_scheme),
):
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Build the query to fetch users and their associated companies
    db = SessionLocal()
    users_with_company = (
        db.query(User)
        .outerjoin(Company, User.id == Company.user_id)
        .options(joinedload(User.company))
        .filter(User.status == "deleted")  # Exclude users with status "deleted"
        .all()
    )
    return users_with_company




################################# ADD USER #########################
@app.post("/api/admin/add-user", response_model=dict)
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
            ))

            return {
                "message": "User registered successfully",
                "id": db_user,
                "username": user.username,
                "email": user.email,
                "role": user.role,
            }

################################# DELETE USER #########################
@app.delete("/api/admin/delete-user/{user_id}", response_model=dict)
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
    if user_to_delete.status =="deleted":
        raise HTTPException(status_code=404, detail="User not found")

    # Delete the associated records in the ResumeData table

    # Delete the user
    user_to_delete.status = "deleted"
    db.commit()

    return {"message": "User deleted successfully", "user_id": user_id}

################################# ADMIN LOGIN #########################
@app.post("/api/admin/login", response_model=dict)
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
    elif user["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is blocked",
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

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "email": user.email,
        }


################################# VIEW USER PROFILE #########################
@app.get('/api/admin/view-user/{user_id}')
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


################################# FORGOT PASSWORD #########################
@app.post("/api/forgot-password")
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
@app.post("/api/reset-password")
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

################################# EDIT USER PROFILE #########################
@app.put("/api/admin/edit-user")
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

    # Update the user's basic information
    query = update(User.__table__).where(User.id == user_id).values(
        username=username, role=role, status=status
    )
    await database.execute(query)

    # Update user services (assuming there's a Many-to-Many relationship between User and Services)


    return {
        "message": "User updated successfully"
    }
@app.post("/api/register-admin")
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



########################################################## SERVICES ###################################################################################################
@app.post("/api/services/create-service")
async def create_service(name: str, description: str, db: Session = Depends(get_db)):
    """
    Create a service

    Args:
        name (String): Name of the service
        description (String): Description of the service
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response giving details of the service.
    """
    try:
        new_service = Service(name=name, description=description)
        db.add(new_service)
        db.commit()
        db.refresh(new_service)
        return new_service
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Service with this name already exists")


@app.delete("/api/services/delete-service/{service_id}")
async def delete_service(service_id: int, db: Session = Depends(get_db)):
    """
    Delete an existing service.

    Args:
        service_id (int): The ID of the service to be deleted..
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    service = db.query(Service).filter(Service.service_id == service_id).first()
    if service:
        db.delete(service)
        db.commit()
        return {"message": "Service deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Service not found")


@app.post("/api/users/assign_services")
async def assign_services_to_user(user_id: int, service_ids: List[int], db: Session = Depends(get_db)):
    """
    Assign multiple services to a user.

    Args:
        user_id (int): The ID of the user.
        service_ids (List[int]): A list of service IDs to be assigned to the user.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    # Fetch the user from the database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Fetch services from the database based on service_ids
    services = db.query(Service).filter(Service.service_id.in_(service_ids)).all()

    if len(services) != len(service_ids):
        raise HTTPException(status_code=404, detail="Some services not found")

    # Clear existing user services
    db.query(UserServices).filter(UserServices.user_id == user_id).delete()

    # Assign services to the user
    for service_id in service_ids:
        user_service = UserServices(user_id=user_id, service_id=service_id)
        db.add(user_service)

    db.commit()

    return {"message": "Services assigned to user successfully"}

@app.delete("/api/users/{user_id}/remove_service/{service_id}")
async def remove_service_from_user(user_id: int, service_id: int, db: Session = Depends(get_db)):
    """
    Remove a service from a user.

    Args:
        user_id (int): The ID of the user.
        service_id (int): The ID of the service to be removed from the user.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    user_service = db.query(UserServices).filter(UserServices.user_id == user_id,
                                                 UserServices.service_id == service_id).first()
    if user_service is None:
        raise HTTPException(status_code=404, detail="Service not found for this user")

    db.delete(user_service)
    db.commit()

    return {"message": "Service removed from user successfully"}


@app.get("/api/services/all-services")
async def get_all_services(db: Session = Depends(get_db)):
    """
    Get all available services.

    Args:
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        List[Service]: A list of all available services.
    """
    services = db.query(Service).all()
    return services


@app.get("/api/users/{user_id}/services")
async def get_user_services(user_id: int, db: Session = Depends(get_db)):
    """
    Get all services associated with a specific user.

    Args:
        user_id (int): The ID of the user.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        List[Service]: A list of services associated with the user.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user.services


@app.put("/api/services/update-service/{service_id}")
async def update_service(service_id: int, service_data: dict, db: Session = Depends(get_db)):
    """
    Update an existing service.

    Args:
        service_id (int): The ID of the service to be updated.
        service_data (dict): The updated service data.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    # Retrieve the service from the database
    service = db.query(Service).filter(Service.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    # Update the service attributes
    for key, value in service_data.items():
        setattr(service, key, value)

    # Commit the changes to the database
    db.commit()

    return {"message": "Service updated successfully"}


@app.get("/api/services/{service_id}")
async def get_service(service_id: int, db: Session = Depends(get_db)):
    """
    Get information about a particular service by its ID.

    Args:
        service_id (int): The ID of the service to retrieve.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response containing information about the service.
    """
    # Retrieve the service from the database
    service = db.query(Service).filter(Service.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    # Convert the service object to a dictionary
    service_info = {
        "service_id": service.service_id,
        "service_name": service.name,
        "service_description": service.description,
        # Add more attributes as needed
    }

    return service_info

########################################################################## COMPNIES ###########################################################################

# Endpoint to create new company
@app.post("/api/companies/create-company")
def create_company(name: str, location: str, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Create Company

    Endpoint: POST api/companies/create-company
    Description: Creates a new company with the provided name, location, and user ID.
    Parameters:
    name: Name of the company (string)
    location: Location of the company (string)
    Returns: The newly created company object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Create the company
    company = Company(name=name, location=location, user_id=current_user.id)
    db.add(company)
    db.commit()
    db.refresh(company)

    return {
        "id": company.id,
        "name": company.name,
        "location": company.location,
        "user_id": company.user_id
    }
# Endpoint to remove a company by its ID
@app.delete("/api/companies/delete-company/{company_id}")
def delete_company(company_id: int, db: Session = Depends(get_db)):
    """
    Delete Company

    Endpoint: DELETE /companies/{company_id}
    Description: Deletes the company with the specified ID.
    Parameters:
    company_id: ID of the company to delete (integer)
    Returns: A message indicating the deletion was successful.
    """
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    db.delete(company)
    db.commit()
    return {"message": "Company deleted successfully"}

# Endpoint to update a company's information
@app.put("/api/companies/update-company/{company_id}")
def update_company(company_id: int, name: str = None, location: str = None, db: Session = Depends(get_db)):
    """
Update Company

Endpoint: PUT /companies/{company_id}
Description: Updates the information of the company with the specified ID.
Parameters:
company_id: ID of the company to update (integer)
name (optional): New name of the company (string)
location (optional): New location of the company (string)
Returns: The updated company object.
    """
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    if name:
        company.name = name
    if location:
        company.location = location
    db.commit()
    db.refresh(company)
    return company

# Endpoint to get information about a specific company
@app.get("/api/companies/{company_id}")
def get_company(company_id: int, db: Session = Depends(get_db)):
    """
    Get Company

Endpoint: GET /companies/{company_id}
Description: Retrieves information about the company with the specified ID.
Parameters:
company_id: ID of the company to retrieve (integer)
Returns: The company object containing its name, location, and associated user ID.
"""
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return company

# Endpoint to get the company of a user
@app.get("/api/user/company/")
def get_user_company(token: str = Depends(oauth2_scheme)):
    """
    Get company of the user
    :param db: Database session
    :param token: User token
    :return: Company details
    """
    db = SessionLocal()
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    company = db.query(Company).filter(Company.user_id == user.id).first()

    # If company is not found, raise HTTP exception
    if not company:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User has not registered a company")

    # Return the company details
    return company

# Endpoint to get all companies
@app.get("/api/companies/")
def get_all_companies(db: Session = Depends(get_db)):
    """
    Get All Companies

    Endpoint: GET /api/companies/
    Description: Retrieves all companies from the database.
    Returns: List of all companies.
    """

    companies = db.query(Company).all()
    return companies


@app.get("/api/admin/resume-history")
def get_resume_history(db: Session = Depends(get_db)):
    """
    Retrieves a list of all resume history data.
    Method: GET
    URL: /resume/history
    Response: Returns a JSON array containing resume history
    data.Each object in the array represents a single resume
    entry and includes information such as the user ID,
    extracted data, and upload datetime.
    """
    return methods.get_all_resume_data(db)


###################################### UPDATE USER PROFILE ######################################
@app.put("/api/update-profile")
async def update_profile(
    profile_picture: UploadFile = File(None),
    username: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    token: str = Depends(oauth2_scheme)
):
    # Open database session
    db = SessionLocal()
    try:
        # Get the user from the database
        user = get_user_from_token(token)
        if not user:
            return {"message": "User not found"}

        # Update profile picture if provided
        if profile_picture:
            profile_picture_path = methods.save_profile_picture(profile_picture)
            user.profile_picture = profile_picture_path

        # Update other user details if provided
        if username:
            user.username = username
        if email:
            user.email = email
        if password:
            user.hashed_password = methods.get_password_hash(password)

        # Commit changes to the database
        db.commit()
        return {"message": "User profile updated successfully"}

    finally:
        # Close database session
        db.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
