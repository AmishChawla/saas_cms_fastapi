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


resume_parser_v2 = APIRouter(prefix="/api/resume_parser_v2")



################################### PARSE RESUME #######################################

@resume_parser_v2.post("/add-resume")
async def add_resume(
        json_data: list = Body(..., embed=True),
        token: str = Depends(oauth2_scheme)
):
    db = SessionLocal()
    user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=user.id):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    if not access_management.check_user_access(user=user, allowed_permissions=['access_resume_parser']):
        raise HTTPException(status_code=403, detail="User does not have access to this service")

    new_resume_collection = schemas.ResumeCollection(
        user_id=user.id,
        extracted_data=json_data,
        upload_datetime=datetime.datetime.utcnow()
    )

    db.add(new_resume_collection)
    db.commit()
    db.refresh(new_resume_collection)
    return {
        "id": new_resume_collection.id,
        "user_id": new_resume_collection.user_id,
        "extracted_data": new_resume_collection.extracted_data,
        "datetime": datetime.datetime.utcnow(),
    }


#################################### RESUME HISTORY ##############################################

@resume_parser_v2.get("/resumes-history")
async def read_user_resumes(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):

    try:
        user = get_user_from_token(token)
        if not methods.is_service_allowed(user_id=user.id):
            raise HTTPException(status_code=403, detail="User does not have access to this service")

        if not access_management.check_user_access(user=user, allowed_permissions=['access_resume_parser']):
            raise HTTPException(status_code=403, detail="User does not have access to this service")

        records = db.query(schemas.ResumeCollection).filter(schemas.ResumeCollection.user_id == user.id).all()
        if not records:
            raise HTTPException(status_code=404, detail="No records found for this user")
        return records
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




