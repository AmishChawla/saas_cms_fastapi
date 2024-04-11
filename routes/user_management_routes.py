from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
import methods
from schemas import User, get_db, SessionLocal, Company
from models import  UserCreate, TokenData
from methods import get_password_hash, get_current_user, oauth2_scheme, get_user_from_token
from sqlalchemy import update
from fastapi_cache.decorator import cache
from fastapi_cache import FastAPICache



user_management_router = APIRouter()

@user_management_router.get("/api/admin/users")
@cache()
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

################################# GET ALL TRASH USERS #########################
@user_management_router.get("/api/admin/trash-users")
@cache()
async def get_all_trash_users(
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
@user_management_router.post("/api/admin/add-user", response_model=dict)
async def admin_add_user(user: UserCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Check if the email is already registered
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create a new user
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password,
                    role=user.role, status="active")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    FastAPICache.delete_url("/api/admin/users")

    return {
        "message": "User registered successfully",
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role,
    }


################################# MOVE USER TO TRASH #########################
@user_management_router.delete("/api/admin/trash-user/{user_id}", response_model=dict)
async def admin_trash_user(
        user_id: int,
        current_user: TokenData = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Endpoint to allow an admin to move a user to trash.
    """
    # Check if the current user is an admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Check if the user to be deleted exists
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if user_to_delete.status == "deleted":
        raise HTTPException(status_code=404, detail="User not found")

    # Delete the associated records in the ResumeData table

    # Delete the user
    user_to_delete.status = "deleted"
    db.commit()
    FastAPICache.delete_url("/api/admin/users")
    FastAPICache.delete_url("/api/admin/trash-users")

    return {"message": "User deleted successfully", "user_id": user_id}

################################# RESTORE USER #########################
@user_management_router.put("/api/admin/restore-user/{user_id}", response_model=dict)
async def admin_delete_user(
        user_id: int,
        current_user: TokenData = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Endpoint to allow an admin to restore a user from trash.
    """
    # Check if the current user is an admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Check if the user to be deleted exists
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if user_to_delete.status == "active":
        raise HTTPException(status_code=404, detail="User already active")

    # Delete the associated records in the ResumeData table

    # Delete the user
    user_to_delete.status = "active"
    db.commit()
    FastAPICache.delete_url("/api/admin/users")
    FastAPICache.delete_url("/api/admin/trash-users")

    return {"message": "User restored successfully", "user_id": user_id}


################################# DELETE USER PERMANENTLY #########################
@user_management_router.delete("/api/admin/delete-user/{user_id}", response_model=dict)
async def admin_delete_user(
        user_id: int,
        current_user: TokenData = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Endpoint to allow an admin to delete a user permanently.
    """
    # Check if the current user is an admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Check if the user to be deleted exists
    user_to_delete = db.query(User).filter(User.id == user_id).first()

    # Delete the associated records in the ResumeData table

    # Delete the user
    db.delete(user_to_delete)
    db.commit()
    FastAPICache.delete_url("/api/admin/trash-users")

    return {"message": "User deleted successfully", "user_id": user_id}



################################# VIEW USER PROFILE #########################
@user_management_router.get('/api/admin/view-user/{user_id}')
@cache()
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

################################# EDIT USER PROFILE #########################
@user_management_router.put("/api/admin/edit-user")
async def edit_user(
        user_id: int,
        username: str,
        role: str,
        status: str,
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    # Verify token and get user from the database
    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    # Update the user's basic information
    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")

    user_to_update.username = username
    user_to_update.role = role
    user_to_update.status = status
    db.commit()
    FastAPICache.delete_url("/api/admin/view-user/{user_id}")
    FastAPICache.delete_url("/api/user-profile")

    # Update user services (assuming there's a Many-to-Many relationship between User and Services)
    # You need to implement this part based on your data model

    return {
        "message": "User updated successfully"
    }


################################################# USER PROFILE ###########################################################
@user_management_router.get('/api/user-profile')
@cache()
async def user_profile(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Ensure that the user and related resume_data are loaded in the same session
    user = db.query(User).options(joinedload(User.resume_data)).filter_by(token=token).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Fetch user services
    user_services = db.execute(
        """
        SELECT s.*
        FROM services s
        INNER JOIN user_services us ON s.service_id = us.service_id
        WHERE us.user_id = :user_id
        """,
        {"user_id": user.id}
    ).fetchall()

    # Fetch company details
    company = db.query(Company).filter_by(user_id=user.id).first()

    #Fetch subscription details
    current_active_plans = []
    subscriptions = user.subscriptions
    for subscription in subscriptions:
        current_plan = methods.get_current_plan_details(stripe_subscription_id=subscription.stripe_subscription_id, db=db)
        current_active_plans.append(current_plan)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "profile_picture": user.profile_picture,
        "token": user.token,
        "resume_data": user.resume_data,
        "status": user.status,
        "services": [{"id": service.service_id, "name": service.name} for service in user_services],
        "current_plans": current_active_plans,
        "company": {"id": company.id, "name": company.name} if company else None
    }


###################################### UPDATE USER PROFILE ######################################
@user_management_router.put("/api/update-profile")
async def update_profile(
        profile_picture: UploadFile = File(None),
        username: Optional[str] = Form(None),
        email: Optional[str] = Form(None),
        password: Optional[str] = Form(None),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    try:
        # Get the user from the database
        user = get_user_from_token(token)
        if not user:
            return {"message": "User not found"}

        # Prepare the update query
        update_values = {}
        if username is not None:
            update_values[User.username.name] = username
        if email is not None:
            update_values[User.email.name] = email
        if password is not None:
            update_values[User.hashed_password.name] = get_password_hash(password)

        # Execute the update query
        if update_values:
            update_query = (
                update(User)
                .where(User.id == user.id)
                .values(update_values)
            )
            db.execute(update_query)

        # Update profile picture if provided
        if profile_picture:
            profile_picture_path = methods.save_profile_picture(profile_picture)
            user.profile_picture = profile_picture_path

        # Commit changes to the database
        db.commit()
        FastAPICache.delete_url("/api/admin/view-user/{user_id}")
        FastAPICache.delete_url("/api/user-profile")

        return {"message": "User profile updated successfully"}

    except Exception as e:
        # Rollback changes if an error occurs
        db.rollback()
        return {"message": str(e)}
    finally:
        # Close the database session
        db.close()

