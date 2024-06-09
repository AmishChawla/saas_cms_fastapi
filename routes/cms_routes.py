import datetime
import io
import json
import math
import tempfile
from pdfminer.high_level import extract_text
from fastapi import APIRouter, FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Path, Body, Query, Form
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
import schemas
from schemas import User, ResumeData, get_db, SessionLocal, PasswordReset, Service, UserServices, Company
from models import UserResponse, UserCreate, Token, TokenData, UserFiles, AdminInfo, UsersResponse, UserCompanyResponse
from constants import DATABASE_URL, ACCESS_TOKEN_EXPIRE_MINUTES
from methods import get_password_hash, verify_password, create_access_token, get_current_user, oauth2_scheme, \
    get_user_from_token, update_user_password
from sqlalchemy import update, select, func
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
import stripe

cms_router = APIRouter()


@cms_router.post("/api/posts/create-post")
def create_post(post: models.PostCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Create Post

    Endpoint: POST /api/posts/create-post
    Description: Creates a new post with the provided title, content, user ID, category ID, subcategory ID, and tag ID.
    Parameters:
    - post: The post data (title, content, category_id, subcategory_id, tag_id)
    - token: The authentication token
    Returns: The newly created post object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if current_user.role == 'user':

        if not methods.is_service_allowed(user_id=current_user.id):
            raise HTTPException(status_code=403, detail="User does not have access to this service")
    # Create the post

        if not methods.is_service_allowed(user_id=current_user.id, service_name="CMS"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="User does not have access to this service")


    # Create the post
    new_post = schemas.Post(
        title=post.title,
        content=post.content,
        user_id=current_user.id,
        author_name=current_user.username,
        created_at=datetime.datetime.utcnow(),
        category_id=post.category_id,
        subcategory_id=post.subcategory_id,
        tag_id=post.tag_id  # Include tag_id
    )

    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    return new_post


@cms_router.delete("/api/posts/delete-post/{post_id}")
def delete_post(post_id: int, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Delete Post

    Endpoint: DELETE /api/posts/delete-post/{post_id}
    Description: Deletes a post by its ID.
    Parameters:
    - post_id: The ID of the post to delete.
    - token: The authentication token
    Returns: The deleted post object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    # Retrieve the post
    db_post = db.query(schemas.Post).filter(schemas.Post.id == post_id).first()
    if not db_post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Check if the current user is the owner of the post
    if db_post.user_id != current_user.id and current_user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to delete this post")

    # Delete the post
    db.delete(db_post)
    db.commit()

    return "Post is deleted successfully"



@cms_router.put("/api/posts/update-post/{post_id}")
def update_post(post_id: int, post: models.PostCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Update Post

    Endpoint: PUT /api/posts/update-post/{post_id}
    Description: Updates the content of a post by its ID.
    Parameters:
    - post_id: The ID of the post to update.
    - post: The updated post data (title, content, category_id, subcategory_id, tag_id)
    - token: The authentication token
    Returns: The updated post object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if current_user.role == 'user':
        if not methods.is_service_allowed(user_id=current_user.id, service_name="CMS"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="User does not have access to this service")

    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    # Retrieve the post
    db_post = db.query(schemas.Post).filter(schemas.Post.id == post_id).first()
    if not db_post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Check if the current user is the owner of the post
    if db_post.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to update this post")

    # Update the post
    db_post.title = post.title
    db_post.content = post.content
    db_post.category_id = post.category_id
    db_post.subcategory_id = post.subcategory_id
    db_post.tag_id = post.tag_id  # Include tag_id

    db.commit()
    db.refresh(db_post)

    return db_post


@cms_router.get("/api/all-posts")
def view_all_posts(db: Session = Depends(get_db)):
    """
    Get All Posts

    Endpoint: GET /api/all-posts/
    Description: Retrieves all posts from the database.
    Returns: List of all posts.
    """
    try:

        posts = db.query(schemas.Post).all()
        return posts
    except Exception as e:
        print(e)


@cms_router.get("/api/posts/{post_id}")
def get_post(post_id: int, db: Session = Depends(get_db)):
    """
    Get Post

Endpoint: GET /posts/{post_id}
Description: Retrieves information about the post with the specified ID.
Parameters:
post_id: ID of the post to retrieve (integer)
Returns: The post object containing its name, location, and associated user ID.
"""
    posts = db.query(schemas.Post).filter(schemas.Post.id == post_id).first()
    if not posts:
        raise HTTPException(status_code=404, detail="Post not found")
    return posts


@cms_router.get("/api/user-all-posts")
def get_all_posts(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get All Posts of a User

    Endpoint: GET /api/get_all-posts/{user_id}/
    Description: Retrieves all posts of a specific user from the database.
    Returns: List of all posts of the specified user.
    """
    try:
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        posts = db.query(schemas.Post).options(
            joinedload(schemas.Post.category),
            joinedload(schemas.Post.subcategory),
            joinedload(schemas.Post.tag)
        ).filter(schemas.Post.user_id == user.id).all()

        return posts
    except Exception as e:
        print(e)

@cms_router.get("/api/user-posts/{username}")
def get_posts_by_username(username: str, db: Session = Depends(get_db)):
    """
    Get All Posts by Username

    Endpoint: GET /api/user-posts/{username}/
    Description: Retrieves all posts of a specific user from the database by their username.
    Returns: List of all posts of the specified user.
    """
    try:
        user = db.query(schemas.User).filter(schemas.User.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        posts = db.query(schemas.Post).options(
            joinedload(schemas.Post.category),
            joinedload(schemas.Post.subcategory),
            joinedload(schemas.Post.tag)
        ).filter(schemas.Post.user_id == user.id).all()

        return posts
    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

@cms_router.get("/api/categories/")
def get_all_categories(db: Session = Depends(get_db)):
    categories = db.query(schemas.Category).all()
    return categories


@cms_router.get("/api/categories/{category_id}/subcategories/")
def get_subcategories_by_category(category_id: int, db: Session = Depends(get_db)):
    subcategories = db.query(schemas.SubCategory).filter(schemas.SubCategory.category_id == category_id).all()
    if not subcategories:
        raise HTTPException(status_code=404, detail="Subcategories not found")
    return subcategories


@cms_router.post("/api/user/create_category")
def create_category(request: models.CategoryCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Create a new category instance
    current_user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    new_category = schemas.Category(category=request.category, user_id=current_user.id)

    # Add and commit the new category to the database
    db.add(new_category)
    db.commit()
    db.refresh(new_category)

    return new_category

@cms_router.get("/api/user-all-categories")
def get_user_all_categories(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get All Posts of a User

    Endpoint: GET /api/all-posts/{user_id}/
    Description: Retrieves all posts of a specific user from the database.
    Returns: List of all posts of the specified user.
    """
    try:
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        categories = db.query(schemas.Category).filter(schemas.Category.user_id == user.id).all()
        return categories
    except Exception as e:
        print(e)


@cms_router.delete("/api/category/delete-category/{category_id}")
def delete_user_category(category_id: int, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Delete Category

    Endpoint: DELETE /api/category/delete-category/{category_id}
    Description: Deletes a category by its ID.
    Parameters:
    - category_id: The ID of the category to delete.
    - token: The authentication token
    Returns: The deleted category object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    # Retrieve the post
    db_category = db.query(schemas.Category).filter(schemas.Category.id == category_id).first()
    if not db_category:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

    # Check if the current user is the owner of the category
    if db_category.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to delete this post")

    # Delete the post
    db.delete(db_category)
    db.commit()

    return "Category is deleted successfully"


@cms_router.put("/api/category/update-category/{category_id}")
def update_user_category(category_id: int, request: models.CategoryCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Update Category

    Endpoint: PUT /api/category/update-category/{category_id}
    Description: Updates a category by its ID.
    Parameters:
    - category_id: The ID of the category to update.
    - request: The new category data.
    - token: The authentication token.
    Returns: The updated category object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    # Retrieve the category
    db_category = db.query(schemas.Category).filter(schemas.Category.id == category_id).first()
    if not db_category:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")

    # Check if the current user is the owner of the category
    if db_category.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to update this category")

    # Update the category with new data
    db_category.category = request.category

    # Commit the changes to the database
    db.commit()
    db.refresh(db_category)

    return db_category


@cms_router.post("/api/user/create_subcategory")
def create_subcategory(request: models.SubcategoryCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Create a new category instance
    current_user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    new_subcategory = schemas.SubCategory(subcategory=request.subcategory, category_id= request.category_id, user_id=current_user.id)

    # Add and commit the new category to the database
    db.add(new_subcategory)
    db.commit()
    db.refresh(new_subcategory)

    return new_subcategory



@cms_router.put("/api/user/update_subcategory/{subcategory_id}")
def update_subcategory(subcategory_id: int, request: models.SubcategoryCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    subcategory = db.query(schemas.SubCategory).filter(schemas.SubCategory.id == subcategory_id, schemas.SubCategory.user_id == current_user.id).first()

    if not subcategory:
        raise HTTPException(status_code=404, detail="Subcategory not found or not authorized")

    subcategory.subcategory = request.subcategory
    subcategory.category_id = request.category_id

    db.commit()
    db.refresh(subcategory)

    return subcategory


@cms_router.delete("/api/user/delete_subcategory/{subcategory_id}")
def delete_subcategory(subcategory_id: int, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = get_user_from_token(token)

    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    subcategory = db.query(schemas.SubCategory).filter(schemas.SubCategory.id == subcategory_id, schemas.SubCategory.user_id == current_user.id).first()

    if not subcategory:
        raise HTTPException(status_code=404, detail="Subcategory not found or not authorized")

    db.delete(subcategory)
    db.commit()

    return {"detail": "Subcategory deleted successfully"}



@cms_router.post("/api/user/add-tags")
def add_tags(request: models.TagAdd, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Create a new category instance
    current_user = get_user_from_token(token)
    new_tag = schemas.Tag(tag=request.tag, user_id=current_user.id)

    # Add and commit the new category to the database
    db.add(new_tag)
    db.commit()
    db.refresh(new_tag)

    return new_tag


@cms_router.put("/api/user/edit-tag/{tag_id}")
def edit_tag(tag_id: int, request: models.TagAdd, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Get the current user from the token
    current_user = get_user_from_token(token)

    # Fetch the tag from the database
    tag = db.query(schemas.Tag).filter(schemas.Tag.id == tag_id, schemas.Tag.user_id == current_user.id).first()

    # Check if the tag exists and belongs to the current user
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found or you do not have permission to edit this tag")

    # Update the tag's details
    tag.tag = request.tag

    # Commit the changes to the database
    db.commit()
    db.refresh(tag)

    return tag


@cms_router.delete("/api/user/delete-tag/{tag_id}")
def delete_tag(tag_id: int, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Get the current user from the token
    current_user = get_user_from_token(token)

    # Fetch the tag from the database
    tag = db.query(schemas.Tag).filter(schemas.Tag.id == tag_id, schemas.Tag.user_id == current_user.id).first()

    # Check if the tag exists and belongs to the current user
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found or you do not have permission to delete this tag")

    # Delete the tag
    db.delete(tag)
    db.commit()

    return {"detail": "Tag deleted successfully"}



@cms_router.get("/api/user-all-tags")
def get_user_all_tags(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get All Posts of a User

    Endpoint: GET /api/all-posts/{user_id}/
    Description: Retrieves all posts of a specific user from the database.
    Returns: List of all posts of the specified user.
    """
    try:
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        tags = db.query(schemas.Tag).filter(schemas.Tag.user_id == user.id).all()
        return tags
    except Exception as e:
        print(e)


@cms_router.get('/api/category/{category_id}')
def get_category_name(category_id, db: Session = Depends(get_db)):
    category = db.query(schemas.Category).filter(schemas.Category.id == category_id).first()
    return category.category

@cms_router.get('/api/subcategory/{subcategory_id}')
def get_subcategory_name(subcategory_id, db: Session = Depends(get_db)):
    subcategory = db.query(schemas.SubCategory).filter(schemas.SubCategory.id == subcategory_id).first()
    return subcategory.subcategory
