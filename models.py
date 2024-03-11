from typing import Union, List
from pydantic import BaseModel
from datetime import datetime


class TokenData(BaseModel):
    username: Union[str, None] = None
    role: Union[str, None] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_datetime: datetime
    status: str
    company_id: int


class UsersResponse(BaseModel):
    users: List[UserResponse]
    total_pages: int


class ResumeDataBase(BaseModel):
    user_id: int
    extracted_data: dict
    csv_file: bytes
    xml_file: bytes
    upload_datetime: datetime
    pdf_resumes: List[bytes]


class ResumeData(ResumeDataBase):
    id: int


class UserFiles(BaseModel):
    user_id: int
    csv_files: List[ResumeData]
    xml_files: List[ResumeData]


class PdfFiles(BaseModel):
    file_name: str
    file_data: bytes
    upload_datetime: datetime
    user_id: int


class AdminInfo(BaseModel):
    username: str
    email: str
    password: str
    role: str = "admin"


class Company(BaseModel):
    name: str
    location: str
    created_at: datetime
    user_id: int


class UserCompanyResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_datetime: datetime
    status: str
    company_id: int = None
    company_name: str = None
    company_location: str = None

############################################################ EMAIL SETTINGS ###############################################################
class SMTPSettingsBase(BaseModel):
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    sender_email: str


class SMTPSettings(SMTPSettingsBase):
    id: int
    user_id: int

    class Config:
        orm_mode = True