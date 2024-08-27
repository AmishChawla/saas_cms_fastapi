
import datetime
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Path, Body, Query, Form, APIRouter
from fastapi.security import OAuth2PasswordRequestForm

from datetime import timedelta
from sqlalchemy.orm import Session, joinedload, selectinload
import methods
import schemas
from schemas import User, ResumeData, get_db, SessionLocal, PasswordReset, Service, UserServices, Company
from models import UserResponse, UserCreate, Token, TokenData, UserFiles, AdminInfo, UsersResponse, UserCompanyResponse
from constants import DATABASE_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from methods import get_password_hash, verify_password, create_access_token, get_current_user, oauth2_scheme, \
    get_user_from_token, update_user_password
import access_management


auth_router = APIRouter()


@auth_router.post("/api/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the email is already registered
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create a new user
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password,
                    role=user.role, status="active", created_datetime=datetime.datetime.utcnow(), group_id=2)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role,
        "created_datetime": new_user.created_datetime,
        "status": new_user.status,
    }


@auth_router.post("/api/login", response_model=dict)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Authenticate user using email

    user = db.query(User).filter(User.email == form_data.username).first()
    user_group = db.query(schemas.Group).filter(schemas.Group.id == user.group_id).first()
    permissions = user_group.permissions

    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user.role != "user":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Insufficient privileges",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is blocked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user.status == "deleted":
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
        user_services = db.query(Service).join(UserServices).filter(UserServices.user_id == user.id).all()

        # Fetch company details
        company = db.query(Company).filter(Company.user_id == user.id).first()


        # Update user token
        user.token = access_token
        db.commit()

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "email": user.email,
            "profile_picture": user.profile_picture,
            "services": [{"id": service.service_id, "name": service.name} for service in user_services],
            "company": {"id": company.id, "name": company.name} if company else None,
            "group": {"id": user_group.id, "name": user_group.name, "permissions": user_group.permissions}
        }


@auth_router.get("/api/get-google-user-info")
async def google_login(userinfo: dict, db: Session = Depends(get_db)):
    userinfo.get('email')
    user = db.query(User).filter(User.email == userinfo.get('email')).first()
    if user:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires
        )
        user_services = db.query(Service).join(UserServices).filter(UserServices.user_id == user.id).all()

        # Fetch company details
        company = db.query(Company).filter(Company.user_id == user.id).first()
        user_group = db.query(schemas.Group).filter(schemas.Group.id == user.group_id).first()

        # Update user token
        user.token = access_token
        db.commit()
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "email": user.email,
            "profile_picture": userinfo.get('profile_picture'),
            "services": [{"id": service.service_id, "name": service.name} for service in user_services],
            "company": {"id": company.id, "name": company.name} if company else None,
            "group": {"id": user_group.id, "name": user_group.name, "permissions": user_group.permissions}
        }
    else:
        new_user = User(username=userinfo.get('name'), email=userinfo.get('email'),
                        role='user', status="active", created_datetime=datetime.datetime.utcnow(), group_id=2)

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": new_user.username, "role": new_user.role},
            expires_delta=access_token_expires
        )
        user_services = db.query(Service).join(UserServices).filter(UserServices.user_id == new_user.id).all()

        # Fetch company details
        company = db.query(Company).filter(Company.user_id == new_user.id).first()
        user_group = db.query(schemas.Group).filter(schemas.Group.id == user.group_id).first()

        # Update user token
        new_user.token = access_token

        db.commit()
        print(userinfo.get('picture'))
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": new_user.role,
            "username": new_user.username,
            "email": new_user.email,
            "profile_picture": userinfo.get('picture'),
            "services": [{"id": service.service_id, "name": service.name} for service in user_services],
            "company": {"id": company.id, "name": company.name} if company else None,
            "group": {"id": user_group.id, "name": user_group.name, "permissions": user_group.permissions}
        }


@auth_router.put("/api/update-password")
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


################################# ADMIN LOGIN #########################
@auth_router.post("/api/admin/login", response_model=dict)
async def login_for_admin(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Authenticate user using email
    user = db.query(User).filter(User.email == form_data.username).first()
    user_group = db.query(schemas.Group).filter(schemas.Group.id == user.group_id).first()
    permissions = user_group.permissions

    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    elif user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Insufficient privileges",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user.status != "active":
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

        user.token = access_token
        db.commit()

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "email": user.email,
            "profile_picture": user.profile_picture,
            "group": {"id": user_group.id, "name": user_group.name, "permissions": user_group.permissions}
        }
################################# FORGOT PASSWORD #########################
@auth_router.post("/api/forgot-password")
async def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        # Generate a password reset token and store it in the database
        reset_token = PasswordReset(user_id=user.id)
        db.add(reset_token)
        db.commit()
        print("user detected")
        # Send an email with the reset token
        methods.send_password_reset_email(email, reset_token.token, db_session=db)

        return {
            "reset_token": reset_token.token,
            "message": "Password reset instructions sent to your email"
        }

    raise HTTPException(status_code=404, detail="User not found")


# Endpoint to reset the password based on the provided token
@auth_router.post("/api/reset-password")
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


@auth_router.post("/api/register-admin")
async def register_admin(admin: AdminInfo, db: Session = Depends(get_db)):
    # Check if the email is already registered
    existing_user = db.query(User).filter(User.email == admin.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create a new user
    hashed_password = get_password_hash(admin.password)
    new_user = User(username=admin.username, email=admin.email, hashed_password=hashed_password,
                    role=admin.role, status="active", created_datetime=datetime.datetime.utcnow())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role,
        "created_datetime": new_user.created_datetime,
        "status": new_user.status,
    }


