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

    base_slug = methods.generate_slug(post.title)

    # Ensure the slug is unique for the user
    unique_slug = methods.ensure_unique_slug(base_slug, current_user.id, db)

    # Create the post
    new_post = schemas.Post(
        title=post.title,
        content=post.content,
        user_id=current_user.id,
        author_name=current_user.username,
        created_at=datetime.datetime.utcnow(),
        category_id=post.category_id,
        subcategory_id=post.subcategory_id,
        status=post.status,
        slug=unique_slug
    )

    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    methods.increment_category_count(db=db, category_id=post.category_id)

    if len(post.tags) > 5:
        raise HTTPException(status_code=400, detail="Maximum 5 tags allowed")

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
    Returns: A message confirming the post deletion.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User does not have access to this service")

    # Retrieve the post
    db_post = db.query(schemas.Post).filter(schemas.Post.id == post_id).first()
    if not db_post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Check if the current user is the owner of the post
    if db_post.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You do not have permission to delete this post")

    db_comments = db.query(schemas.Comment).filter(schemas.Comment.post_id == post_id).all()
    for comment in db_comments:
        db.delete(comment)

    db_commentslikes = db.query(schemas.Commentlike).filter(schemas.Commentlike.post_id == post_id).all()
    for commentlike in db_commentslikes:
        db.delete(commentlike)

    # Delete the post
    db.delete(db_post)
    db.commit()

    return {"message": "Post is deleted successfully"}


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


@cms_router.get("/api/all-posts/")
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
        "slug": post.slug,
        "status": post.status,
        "created_at": post.created_at.isoformat(),
        "category_name": category_name,  # Include the category name in the response
    }
    return response_data


@cms_router.get("/api/posts/{username}/{slug}")
def read_post(username: str, slug: str, db: Session = Depends(get_db)):
    # Query the database for a post with the given username and slug
    post = db.query(schemas.Post).join(User).filter(User.username == username, schemas.Post.slug == slug).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    category_name = post.category.category

    methods.increment_post_views(db=db, post_id=post.id)

    response_data = {
        "id": post.id,
        "author_name": post.author_name,
        "title": post.title,
        "content": post.content,
        "category_id": post.category_id,
        "subcategory_id": post.subcategory_id,
        "tags": post.tags,
        "status": post.status,
        "slug": post.slug,
        "created_at": post.created_at.isoformat(),
        "category_name": category_name,  # Include the category name in the response
    }

    # Convert the PostInDB model to PostBase for the response
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
def delete_tag_from_db(tag_id: int, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    db_tag = tags_crud.get_tag(db=db, tag_id=tag_id)
    if db_tag is None:
        raise HTTPException(status_code=404, detail="Tag not found")

    db_tag = tags_crud.delete_tag_user_association(db, tag_id=tag_id, user_id=current_user.id)
    return "deleted"


@cms_router.get("/api/user-tags/")
def user_all_tags(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Query to get all tags related to the user, ordered by created_at DESC

    tags = db.query(schemas.Tag, schemas.TagUser.post_count). \
        join(schemas.TagUser). \
        filter(schemas.TagUser.user_id == current_user.id). \
        order_by(schemas.Tag.created_at.desc()). \
        all()

    # Convert tags to a list of dictionaries for JSON serialization

    return tags


@cms_router.get("/api/posts-by-tag/{username}/{tag_id}")
def post_by_tag(tag_id: int, username: str, db: Session = Depends(get_db)):
    try:
        posts = tags_crud.get_posts_by_tag(db, tag_id, username)
        return posts
    except Exception as e:
        raise e


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

@cms_router.delete("/api/posts/delete-comment/{comment_id}")
def delete_comment(comment_id: int, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Delete Comment

    Endpoint: DELETE /api/posts/delete-comment/{comment_id}
    Description: Deletes a comment by its ID.
    Parameters:
    - comment_id: The ID of the comment to delete.
    - token: The authentication token
    Returns: A message confirming the comment deletion.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not methods.is_service_allowed(user_id=current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User does not have access to this service")

    db_comments = db.query(schemas.Comment).filter(schemas.Comment.id == comment_id).first()

    db_commentslikes = db.query(schemas.Commentlike).filter(schemas.Commentlike.comment_id == comment_id).all()
    for commentlike in db_commentslikes:
        db.delete(commentlike)

    # Delete the comment
    db.delete(db_comments)
    db.commit()

    return {"message": "Comment is deleted successfully"}

@cms_router.post("/api/user/add_like_to_a_comment")
def add_like_to_a_comment(request: models.AddLike, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Get the current user from the token
    current_user = get_user_from_token(token)

    # Create a new Commentlike instance
    new_like = schemas.Commentlike(post_id=request.post_id, comment_id=request.comment_id, user_id=current_user.id)

    # Add and commit the new like to the database
    db.add(new_like)
    db.commit()
    db.refresh(new_like)

    return {"message": "Comment liked successfully", "like_id": new_like.id}


@cms_router.delete("/api/comments/remove-like/{comment_like_id}")
def remove_like_from_a_comment(comment_like_id: int, token: str = Depends(oauth2_scheme),
                               db: Session = Depends(get_db)):
    # Get the current user from the token
    current_user = get_user_from_token(token)

    # Find the like to be removed
    like = db.query(schemas.Commentlike).filter(
        schemas.Commentlike.id == comment_like_id,
        schemas.Commentlike.user_id == current_user.id
    ).first()

    # Check if the like exists
    if not like:
        raise HTTPException(status_code=404, detail="Like not found")

    # Remove the like from the database
    db.delete(like)
    db.commit()

    return {"message": "Comment like removed successfully"}


@cms_router.get("/api/comment/all")
def get_all_comments(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = get_user_from_token(token)

    # Get all post IDs created by the current user
    user_post_ids = db.query(schemas.Post.id).filter(schemas.Post.user_id == current_user.id).all()
    user_post_ids = [post.id for post in user_post_ids]

    # Get comments for posts created by the current user
    comments = db.query(schemas.Comment).options(
        joinedload(schemas.Comment.posts),
        joinedload(schemas.Comment.user)
    ).filter(schemas.Comment.post_id.in_(user_post_ids)).all()

    return comments


@cms_router.get("/api/comment/by_post_id/{post_id}")
def get_all_comments_by_post_id(post_id: int, db: Session = Depends(get_db)):
    comments = db.query(schemas.Comment).options(
        joinedload(schemas.Comment.posts),
        joinedload(schemas.Comment.user)
    ).filter(schemas.Comment.post_id == post_id).all()
    return comments


@cms_router.get("/api/comment/like/{post_id}")
def get_like_of_a_comment(post_id: int, db: Session = Depends(get_db)):
    comments = db.query(schemas.Commentlike).filter(schemas.Commentlike.post_id == post_id).all()
    return comments


@cms_router.post("/api/comment/toggle_status/{comment_id}")
def toggle_comment_status(comment_id: int,
                          db: Session = Depends(get_db)):
    comment = db.query(schemas.Comment).filter(schemas.Comment.id == comment_id).first()

    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Ensure only the comment author or an admin can change the status

    comment.active = True
    db.commit()
    return {"success": True}


@cms_router.post("/api/comment/deactivate/{comment_id}")
def deactivate_comment(comment_id: int, db: Session = Depends(get_db)):
    comment = db.query(schemas.Comment).filter(schemas.Comment.id == comment_id).first()

    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Ensure only the comment author or an admin can deactivate the comment

    # Deactivate the comment
    comment.active = False
    db.commit()

    return {"message": "Comment deactivated successfully"}


@cms_router.post("/api/settings/update_comment_settings")
def update_comment_settings(
    request: models.CommentSettingsUpdate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Retrieve current user from token
    current_user = get_user_from_token(token)

    # Retrieve existing user settings
    user_settings = db.query(schemas.UserSetting).filter(schemas.UserSetting.user_id == current_user.id).first()
    print(user_settings)
    if user_settings:
        # Update the existing user settings
        user_settings.notify_linked_blogs = request.notify_linked_blogs
        user_settings.allow_trackbacks = request.allow_trackbacks
        user_settings.allow_comments = request.allow_comments
        user_settings.comment_author_info = request.comment_author_info
        user_settings.registered_users_comment = request.registered_users_comment
        user_settings.auto_close_comments = request.auto_close_comments
        user_settings.show_comment_cookies = request.show_comment_cookies
        user_settings.enable_threaded_comments = request.enable_threaded_comments
        user_settings.email_new_comment = request.email_new_comment
        user_settings.email_held_moderation = request.email_held_moderation
        user_settings.email_new_subscription = request.email_new_subscription
        user_settings.comment_approval = request.comment_approval
    else:
        # Create new user settings if they don't exist
        user_settings = schemas.UserSetting(
            user_id=current_user.id,
            notify_linked_blogs=request.notify_linked_blogs,
            allow_trackbacks=request.allow_trackbacks,
            allow_comments=request.allow_comments,
            comment_author_info=request.comment_author_info,
            registered_users_comment=request.registered_users_comment,
            auto_close_comments=request.auto_close_comments,
            show_comment_cookies=request.show_comment_cookies,
            enable_threaded_comments=request.enable_threaded_comments,
            email_new_comment=request.email_new_comment,
            email_held_moderation=request.email_held_moderation,
            email_new_subscription=request.email_new_subscription,
            comment_approval=request.comment_approval
        )
        db.add(user_settings)

    # Commit the changes to the database
    db.commit()
    db.refresh(user_settings)

    return user_settings



@cms_router.get("/api/settings/get_comment_settings")
def get_comments_settings(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Retrieve current user from token
    current_user = get_user_from_token(token)

    # Get the user settings for the current user
    user_comments_settings = db.query(schemas.UserSetting).filter(schemas.UserSetting.user_id == current_user.id).first()

    if not user_comments_settings:
        return {}

    return user_comments_settings


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
def send_newsletter(mail: models.Mail, post_url: str, token: str = Depends(oauth2_scheme),
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
    <a href="{post_url}" class="action-button" style="display: inline-block; padding: 12px 24px; margin: 8px; font-size: 16px; line-height: 1.5; color: #ffffff; background-color: #007bff; border-radius: 4px; text-decoration: none; transition: background-color 0.3s;">Read more</a>
    
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


@cms_router.post("/api/user-contact-form")
def user_contact_form(username: str = Body(..., embed=True),
                      firstname: str = Body(..., embed=True),
                      lastname: str = Body(..., embed=True),
                      email: str = Body(..., embed=True),
                      message: str = Body(..., embed=True), db: Session = Depends(get_db)):
    print('Received data:', username, firstname, lastname, email, message)
    print('start')
    try:
        user = db.query(schemas.User).filter(schemas.User.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.user_id == user.id).first()
        recipient_email = smtp_settings.sender_email
        print(recipient_email)

        if recipient_email:
            message_body = f"""
            From: {firstname} {lastname} <br>
            Email: {email} <br>
            
            {message}
            """
            subject_body = f"Message from {firstname} {lastname}"
            methods.admin_send_email(recipient_emails=[recipient_email], message=message_body, subject=subject_body,
                                     db_session=db)

            new_feedback = schemas.Feedback(firstname=firstname, lastname=lastname, email=email, message=message,
                                            user_id=user.id, created_at=datetime.datetime.utcnow())
            db.add(new_feedback)
            db.commit()
            db.refresh(new_feedback)

        else:
            new_feedback = schemas.Feedback(firstname=firstname, lastname=lastname, email=email, message=message,
                                            user_id=user.id, created_at=datetime.datetime.utcnow())
            db.add(new_feedback)
            db.commit()
            db.refresh(new_feedback)
            return "sorry no contact info"

        return "message sent"

    except HTTPException as http_exc:
        # Re-raise the HTTP exception if it's already one
        raise http_exc

    except Exception as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e)


@cms_router.get("/api/user/all-feedbacks")
def read_user_feedback(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        user = get_user_from_token(token)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        feedback_entries = db.query(schemas.Feedback).filter(schemas.Feedback.user_id == user.id).order_by(
            desc(schemas.Feedback.created_at)).all()

        # Convert the result to a list of dictionaries suitable for JSON serialization

        return feedback_entries

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@cms_router.get("/api/posts/by-category-and-author-name/{category_id}/{author_name}")
def read_posts_by_category_and_author_name_sorted(category_id: int, author_name: str, db: Session = Depends(get_db)):
    """
    Retrieve posts by category ID and author name, sorted by creation date in descending order.

    :param category_id: The ID of the category to filter posts by.
    :param author_name: The name of the author whose posts to retrieve.
    :return: A list of Post objects filtered by the given category ID and author name, sorted by creation date in descending order.
    """
    # Query to fetch posts by category ID and author name, sorted by creation date
    posts = (
        db.query(schemas.Post)
        .join(schemas.Category)
        .filter(schemas.Category.id == category_id, schemas.Post.author_name == author_name)
        .order_by(desc(schemas.Post.created_at))  # Sort by creation date in descending order
        .all()
    )

    if not posts:
        raise HTTPException(status_code=404, detail="No posts found for the specified category and author name.")

    return posts


@cms_router.get("/api/posts/by-tag-and-username/{username}/{tag_id}")
def read_posts_by_tag_and_username(tag_id: int, username: str, db: Session = Depends(get_db)):
    """
    Retrieve posts by a single tag ID and a specific username, sorted by creation date in descending order.

    :param tag_id: The ID of the tag to filter posts by.
    :param username: The username of the author whose posts to retrieve.
    :return: A list of Post objects filtered by the given tag ID and username, sorted by creation date in descending order.
    """
    # Query to fetch posts by tag ID and username, sorted by creation date
    posts = (
        db.query(schemas.Post)
            .join(schemas.TagPost, schemas.TagPost.post_id == schemas.Post.id)
            .join(schemas.Tag, schemas.Tag.id == schemas.TagPost.tag_id)
            .join(User, User.id == schemas.Post.user_id)
            .filter(schemas.TagPost.tag_id == tag_id, User.username == username)
            .order_by(desc(schemas.Post.created_at))
            .all()
    )

    if not posts:
        raise HTTPException(status_code=404, detail="No posts found for the specified tag and username.")

    return posts

