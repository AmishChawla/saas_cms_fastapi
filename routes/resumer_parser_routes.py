import datetime
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
import methods
from schemas import User, ResumeData, get_db, SessionLocal, Service, UserServices, Company
from methods import get_password_hash, verify_password, get_current_user, oauth2_scheme, \
    get_user_from_token


resume_parser_router = APIRouter()


################################### PARSE RESUME #######################################
@resume_parser_router.post("/api/process-resume/")
async def process_resume(

        pdf_files: List[UploadFile] = File(...),
        token: str = Depends(oauth2_scheme),
):
    db = SessionLocal()
    user = get_user_from_token(token)
    if not methods.is_service_allowed(user_id=user.id, service_name="resume_parser"):
        raise HTTPException(status_code=403, detail="User does not have access to this service")


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


#################################### RESUME HISTORY ##############################################
@resume_parser_router.get("/api/admin/resume-history")
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
