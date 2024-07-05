import datetime
import io
import json
import os
import shutil
import math
import tempfile
from pdfminer.high_level import extract_text
from fastapi import APIRouter, FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Path, Body, Query, \
    Form
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
from sqlalchemy import desc

import constants
import methods
import models
import schemas
from crud.posts import tags_crud
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

MEDIA_DIRECTORY = "media/"
os.makedirs(MEDIA_DIRECTORY, exist_ok=True)

newsletter_router = APIRouter(prefix="/api/newsletter")


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
    new_post = schemas.Post(
        title=post.title,
        content=post.content,
        user_id=current_user.id,
        author_name=current_user.username,
        created_at=datetime.datetime.utcnow(),
        category_id=post.category_id,
        subcategory_id=post.subcategory_id,
        status=post.status
    )

    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    for tag in post.tags:
        tag = tags_crud.create_tag(db, tag_create=models.TagCreate(tag=tag), user_id=current_user.id)
        # Associate the tag with the post
        new_post.tags.append(tag)

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to delete this post")

    # Delete the post
    db.delete(db_post)
    db.commit()

    return "Post is deleted successfully"


@cms_router.put("/api/posts/update-post/{post_id}")
def update_post(post_id: int, post: models.PostCreate, token: str = Depends(oauth2_scheme),
                db: Session = Depends(get_db)):
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

        if not methods.is_service_allowed(user_id=current_user.id):
            raise HTTPException(status_code=403, detail="User does not have access to this service")
    # Retrieve the post
    db_post = db.query(schemas.Post).filter(schemas.Post.id == post_id).first()
    if not db_post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Check if the current user is the owner of the post
    if db_post.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to update this post")

    # Update the post
    db_post.title = post.title
    db_post.content = post.content
    db_post.category_id = post.category_id
    db_post.subcategory_id = post.subcategory_id
    db_post.status = post.status

    # Refresh the post to reflect changes
    # db.refresh(db_post)

    # Handle tags update
    # Remove existing tags from the post
    db_post.tags = []
    for tag in post.tags:
        tag = tags_crud.create_tag(db, tag_create=models.TagCreate(tag=tag), user_id=current_user.id)
        # Associate the tag with the post
        db_post.tags.append(tag)

    # Commit the changes
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

        posts = db.query(schemas.Post).options(
            joinedload(schemas.Post.category),
            joinedload(schemas.Post.subcategory),
            joinedload(schemas.Post.tags, innerjoin=True)  # Adjusted for many-to-many relationship
        ).filter(schemas.Post.status == 'published').order_by(desc(schemas.Post.created_at)).all()
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
    post = db.query(schemas.Post).options(joinedload(schemas.Post.category)).filter(schemas.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    category_name = post.category.category

    # Create a dictionary to hold the response data
    response_data = {
        "id": post.id,
        "author_name": post.author_name,
        "title": post.title,
        "content": post.content,
        "category_id": post.category_id,
        "subcategory_id": post.subcategory_id,
        "tags": post.tags,
        "status": post.status,
        "created_at": post.created_at.isoformat(),
        "category_name": category_name,  # Include the category name in the response
    }
    return response_data

@cms_router.get("/api/user-all-posts")
def get_all_posts(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get All Posts of a User

    Endpoint: GET /api/user-all-posts/
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
            joinedload(schemas.Post.tags, innerjoin=True)  # Adjusted for many-to-many relationship
        ).filter(schemas.Post.user_id == user.id).order_by(desc(schemas.Post.created_at)).all()
        print(posts[0])

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
            joinedload(schemas.Post.tags, innerjoin=True)
        ).filter(schemas.Post.user_id == user.id).filter(schemas.Post.status == 'published').order_by(
            desc(schemas.Post.created_at)).all()

        return posts
    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")


@cms_router.get("/api/categories/")
def get_all_categories(db: Session = Depends(get_db)):
    categories = db.query(schemas.Category).order_by(desc(schemas.Category.created_at)).all()
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

        categories = db.query(schemas.Category).filter(schemas.Category.user_id == user.id).order_by(
            desc(schemas.Category.created_at)).all()
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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to delete this post")

    # Delete the post
    db.delete(db_category)
    db.commit()

    return "Category is deleted successfully"


@cms_router.put("/api/category/update-category/{category_id}")
def update_user_category(category_id: int, request: models.CategoryCreate, token: str = Depends(oauth2_scheme),
                         db: Session = Depends(get_db)):
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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to update this category")

    # Update the category with new data
    db_category.category = request.category

    # Commit the changes to the database
    db.commit()
    db.refresh(db_category)

    return db_category


@cms_router.post("/api/user/create_subcategory")
def create_subcategory(request: models.SubcategoryCreate, token: str = Depends(oauth2_scheme),
                       db: Session = Depends(get_db)):
    # Create a new category instance
    current_user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    new_subcategory = schemas.SubCategory(subcategory=request.subcategory, category_id=request.category_id,
                                          user_id=current_user.id)

    # Add and commit the new category to the database
    db.add(new_subcategory)
    db.commit()
    db.refresh(new_subcategory)

    return new_subcategory


@cms_router.put("/api/user/update_subcategory/{subcategory_id}")
def update_subcategory(subcategory_id: int, request: models.SubcategoryCreate, token: str = Depends(oauth2_scheme),
                       db: Session = Depends(get_db)):
    current_user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    subcategory = db.query(schemas.SubCategory).filter(schemas.SubCategory.id == subcategory_id,
                                                       schemas.SubCategory.user_id == current_user.id).first()

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

    subcategory = db.query(schemas.SubCategory).filter(schemas.SubCategory.id == subcategory_id,
                                                       schemas.SubCategory.user_id == current_user.id).first()

    if not subcategory:
        raise HTTPException(status_code=404, detail="Subcategory not found or not authorized")

    db.delete(subcategory)
    db.commit()

    return {"detail": "Subcategory deleted successfully"}


@cms_router.post("/api/tags/")
def create_tag_for_user(tag: models.TagCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    return tags_crud.create_tag(db=db, tag_create=tag, user_id=current_user.id)

@cms_router.get("/api/tags/")
def read_tags(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    tags = tags_crud.get_tags(db, skip=skip, limit=limit)
    return tags

@cms_router.get("/api/tags/{tag_id}")
def read_tag(tag_id: int, db: Session = Depends(get_db)):
    db_tag = tags_crud.get_tag(db, tag_id=tag_id)
    if db_tag is None:
        raise HTTPException(status_code=404, detail="Tag not found")
    return db_tag


@cms_router.put("/api/tags/update/{old_tag_id}")
def update_existing_tag(old_tag_id: int,
                        token: str = Depends(oauth2_scheme),
                        new_tag_details: models.TagUpdate = Body(..., embed=True),
                        db: Session = Depends(get_db)):
    # Perform the update
    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    new_tag = tags_crud.update_tag(db, current_user.id, old_tag_id, new_tag_details)

    if not new_tag:
        raise HTTPException(status_code=404, detail="Tag not found after update attempt.")

    return new_tag


@cms_router.delete("/api/tags/{tag_id}")
def delete_tag_from_db(tag_id: int, db: Session = Depends(get_db),token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    db_tag = tags_crud.get_tag(db=db,tag_id=tag_id)
    if db_tag is None:
        raise HTTPException(status_code=404, detail="Tag not found")

    db_tag = tags_crud.delete_tag_user_association(db, tag_id=tag_id, user_id=current_user.id)
    return "deleted"

@cms_router.get("/api/user-tags/")
def user_all_tags(db: Session = Depends(get_db),token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Query to get all tags related to the user, ordered by created_at DESC

    tags = db.query(schemas.Tag). \
        join(schemas.TagUser). \
        filter(schemas.TagUser.user_id == current_user.id). \
        order_by(schemas.Tag.created_at.desc()). \
        all()

    # Convert tags to a list of dictionaries for JSON serialization

    return tags




@cms_router.get('/api/category/{category_id}')
def get_category_name(category_id, db: Session = Depends(get_db)):
    category = db.query(schemas.Category).filter(schemas.Category.id == category_id).first()
    return category.category


@cms_router.get('/api/subcategory/{subcategory_id}')
def get_subcategory_name(subcategory_id, db: Session = Depends(get_db)):
    subcategory = db.query(schemas.SubCategory).filter(schemas.SubCategory.id == subcategory_id).first()
    return subcategory.subcategory


@cms_router.post("/api/upload-multiple-files/")
def upload_multiple_files(files: List[UploadFile] = File(...), db: Session = Depends(get_db),
                          token: str = Depends(oauth2_scheme)):
    print("ander aa gya")
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    uploaded_filenames = []

    for file in files:
        print(f"File name: {file.filename}, Content Type: {file.content_type}")
        file_location = os.path.join(MEDIA_DIRECTORY, file.filename)
        print(file_location)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Store only the relative path in the database
        relative_path = os.path.relpath(file_location, MEDIA_DIRECTORY)
        print(relative_path)

        new_media = schemas.Media(
            filename=file.filename,
            file_url=file_location,
            user_id=user.id  # Use the user_id from the request or session
        )
        db.add(new_media)
        db.commit()
        db.refresh(new_media)

        uploaded_filenames.cms_routerend(file.filename)

    return {
        "filenames": uploaded_filenames
    }


@cms_router.get("/api/user-all-medias")
def get_user_all_medias(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get All Posts of a User

    Endpoint: GET /api/user-all-medias
    Description: Retrieves all posts of a specific user from the database.
    Returns: List of all posts of the specified user.
    """

    try:
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        medias = db.query(schemas.Media).filter(schemas.Media.user_id == user.id).order_by(
            desc(schemas.Media.uploaded_at)).all()
        return medias
    except Exception as e:
        print(e)


@cms_router.post("/api/post/add_comment")
def add_comment(request: models.CommentCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Retrieve current user from token
    current_user = get_user_from_token(token)

    # Check if user is authorized to add comments (if needed)
    # Example: methods.is_service_allowed(user_id=current_user.id)
    # if not methods.is_service_allowed(user_id=current_user.id):
    #     raise HTTPException(status_code=403, detail="User does not have access to this service")

    # Create a new comment instance
    new_comment = schemas.Comment(
        user_id=current_user.id,
        post_id=request.post_id,
        reply_id=request.reply_id,
        comment=request.comment,

    )

    # Add and commit the new comment to the database
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)

    return new_comment


@cms_router.get("/api/comment/all")
def get_all_comments(db: Session = Depends(get_db)):
    comments = db.query(schemas.Comment).all()
    return comments

@cms_router.get("/api/comment/by_post_id/{post_id}")
def get_all_comments_by_post_id(post_id: int, db: Session = Depends(get_db)):
    comments = db.query(schemas.Comment).options(
            joinedload(schemas.Comment.posts),
            joinedload(schemas.Comment.user)
        ).filter(schemas.Comment.post_id == post_id).all()
    return comments

@newsletter_router.post("/subscribe_newsletter")
def subscribe_newsletter(subscribe_newsletter: models.NewsLetterSubscription, db: Session = Depends(get_db)):
    print('start')
    try:
        user = db.query(schemas.User).filter(schemas.User.username == subscribe_newsletter.username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        existing_subscription = db.query(schemas.NewsLetterSubscription).join(
            schemas.User, schemas.NewsLetterSubscription.user_id == schemas.User.id
        ).filter(
            schemas.User.username == subscribe_newsletter.username,
            schemas.NewsLetterSubscription.subscriber_email == subscribe_newsletter.subscriber_email,
            schemas.NewsLetterSubscription.status == 'active'
        ).first()

        if existing_subscription:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User is already a subscriber.")

        new_subscriber_for_newsletter = schemas.NewsLetterSubscription(
            subscriber_name=subscribe_newsletter.subscriber_name,
            subscriber_email=subscribe_newsletter.subscriber_email,
            user_id=user.id,
            created_at=datetime.datetime.utcnow())
        print('addind to db')

        db.add(new_subscriber_for_newsletter)
        db.commit()
        db.refresh(new_subscriber_for_newsletter)
        return new_subscriber_for_newsletter

    except HTTPException as http_exc:
        # Re-raise the HTTP exception if it's already one
        raise http_exc

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e)


@newsletter_router.get("/newsletter-subscribers-for-user")
def get_newsletter_subscribers_for_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    print('start')

    try:
        user = get_user_from_token(token)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        subscribers = db.query(schemas.NewsLetterSubscription) \
            .filter(schemas.NewsLetterSubscription.user_id == user.id) \
            .order_by(desc(schemas.NewsLetterSubscription.created_at)) \
            .all()
        active_count = db.query(schemas.NewsLetterSubscription) \
            .filter(schemas.NewsLetterSubscription.user_id == user.id) \
            .filter(schemas.NewsLetterSubscription.status == "active") \
            .count()

        # Query to count inactive subscribers
        inactive_count = db.query(schemas.NewsLetterSubscription) \
            .filter(schemas.NewsLetterSubscription.user_id == user.id) \
            .filter(schemas.NewsLetterSubscription.status == "inactive") \
            .count()

        return {
            'subscribers': subscribers,
            'active_sub_count': active_count,
            'inactive_sub_count': inactive_count
        }
    except Exception as e:
        print(e)


@newsletter_router.post("/send-newsletter")
def send_newsletter(mail: models.Mail, token: str = Depends(oauth2_scheme),
                    db: Session = Depends(get_db)):
    print('inside')
    user = get_user_from_token(token)

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not methods.is_service_allowed(user_id=user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    subscribers = db.query(schemas.NewsLetterSubscription.subscriber_email).join(User).filter(
        User.id == user.id).filter(schemas.NewsLetterSubscription.status == 'active').all()
    subscriber_emails = [subscriber[0] for subscriber in subscribers]
    print('got subscriber_list')

    message = f"""
<p>Thank you for subscribing to our newsletter!</p>
{mail.body}
<div style="text-align: center; font-family: Arial, sans-serif;">
    <!-- Visit Button -->
    <a href="{constants.FLASK_URL}/{user.username}/posts" class="action-button" style="display: inline-block; padding: 12px 24px; margin: 8px; font-size: 16px; line-height: 1.5; color: #ffffff; background-color: #007bff; border-radius: 4px; text-decoration: none; transition: background-color 0.3s;">Visit</a>
    
    <!-- Unsubscribe Button -->
    <a href="{constants.FLASK_URL}/unsubscribe-newsletter/{user.username}" class="action-button" style="display: inline-block; font-size: 16px; line-height: 1.5;">Unsubscribe</a>
</div>

    """

    methods.send_email(recipient_emails=subscriber_emails, message=message, subject=mail.subject, db_session=db,
                       role=user.role,
                       user_id=user.id)
    return "Mail Sent Successfully"


@newsletter_router.post("/unsubscribe-newsletter")
def subscribe_newsletter(unsubscribe_newsletter: models.UnsubscribeNewsletter, db: Session = Depends(get_db)):
    print('start')
    try:
        # Perform a join between User and NewsLetterSubscription tables
        # Filter by both the provided email and username
        subscription = db.query(schemas.NewsLetterSubscription). \
            join(schemas.User, schemas.User.id == schemas.NewsLetterSubscription.user_id). \
            filter(schemas.NewsLetterSubscription.subscriber_email == unsubscribe_newsletter.subscriber_email,
                   schemas.User.username == unsubscribe_newsletter.username). \
            first()

        if not subscription:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="User not found or not subscribed to the newsletter")

        # Update the subscription status to inactive
        subscription.status = 'inactive'
        db.commit()
        db.refresh(subscription)
        print(subscription)
        return subscription

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
