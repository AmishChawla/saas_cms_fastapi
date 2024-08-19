from schemas import get_db, SessionLocal
import schemas
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter, Body
from sqlalchemy.orm import Session, joinedload


OWNER_PERMISSIONS = ["manage_user",
                     "list_of_users",
                     "list_of_sites",
                     "owner_email_setup",
                     "manage_subscription_plans",
                     "order_history"]

SITE_ADMIN_PERMISSIONS = ["manage_posts",
                          "manage_comments",
                          "manage_pages",
                          "manage_media",
                          "manage_forms",
                          "access_chatbot",
                          "access_resume_parser"
                          ]

SITE_USER_PERMISSIONS = ["site_user"]


def check_user_access(user: schemas.User, allowed_permissions):
    db = SessionLocal()

    user_group = db.query(schemas.Group).filter(schemas.Group.id == user.group_id).first()
    user_permissions = user_group.permissions
    return any(permission in allowed_permissions for permission in user_permissions)