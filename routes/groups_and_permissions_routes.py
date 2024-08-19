import datetime
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter, Body
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
import methods
from schemas import Group, get_db, User
from methods import get_password_hash, verify_password, get_current_user, oauth2_scheme, \
    get_user_from_token
# from fastapi_cache.decorator import cache
# from fastapi_cache import FastAPICache

access_management_router = APIRouter(prefix="/api/access-management")


@access_management_router.post("/groups/create-group")
def create_group(name: str, permission_names: List[str] = Body(..., embed=True), db: Session = Depends(get_db)):
    group = Group(name=name, permissions=permission_names)
    db.add(group)
    db.commit()
    db.refresh(group)
    db.commit()
    return group


@access_management_router.put("/groups/update-group/{group_id}")
def update_group(group_id: int, name: str, permission_names: List[str] = Body(..., embed=True), db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    group.name = name
    group.permissions = permission_names
    group.updated_at = datetime.datetime.utcnow()

    db.commit()
    return group


@access_management_router.delete("/groups/delete-group/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")


    # Delete the group
    db.delete(group)
    db.commit()

@access_management_router.get("/groups/{group_id}")
def get_security_group(group_id: int, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


@access_management_router.get("/all-groups")
async def read_groups(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    groups = db.query(Group).offset(skip).limit(limit).all()
    return groups


@access_management_router.get("/groups/{group_id}/users/")
async def read_users_in_group(group_id: int, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    users = db.query(User).filter(User.group_id == group_id).all()
    return users


