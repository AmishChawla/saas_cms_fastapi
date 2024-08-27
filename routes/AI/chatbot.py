import datetime
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter,Body
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload

import access_management
import methods
from schemas import User, ResumeData, get_db, SessionLocal, Service, UserServices, Company
from methods import get_password_hash, verify_password, get_current_user, oauth2_scheme, \
    get_user_from_token
import schemas

# from fastapi_cache.decorator import cache
# from fastapi_cache import FastAPICache


chatbot_router = APIRouter(prefix="/api/chatbot")



################################### SAVE CHAT #######################################

@chatbot_router.post("/save-chat")
async def save_chat(
        json_data: list = Body(..., embed=True),
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")
    if not access_management.check_user_access(user=user, allowed_permissions=['access_chatbot']):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    new_chat = schemas.UserChats(
        user_id=user.id,
        messages=json_data,
        upload_datetime=datetime.datetime.utcnow()
    )

    db.add(new_chat)
    db.commit()
    db.refresh(new_chat)
    return {
        "id": new_chat.id,
        "user_id": new_chat.user_id,
        "messages": new_chat.messages,
        "datetime": datetime.datetime.utcnow(),
    }


##################################### ALL CHAT ##############################################

@chatbot_router.get("/all-chats")
async def read_user_resumes(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):

    try:
        user = get_user_from_token(token)
        if not methods.is_service_allowed(user_id=user.id):
            raise HTTPException(status_code=403, detail="User does not have access to this service")
        if not access_management.check_user_access(user=user, allowed_permissions=['access_chatbot']):
            raise HTTPException(status_code=403, detail="User does not have access to this service")

        chats = db.query(schemas.UserChats).filter(schemas.UserChats.user_id == user.id).order_by(schemas.UserChats.upload_datetime.desc()).all()

        if not chats:
            raise HTTPException(status_code=404, detail="No records found for this user")
        return chats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




