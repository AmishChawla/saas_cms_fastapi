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


class ResumeDataBase(BaseModel):
    user_id: int
    extracted_data: dict
    csv_file: bytes
    xml_file: bytes
    upload_datetime: datetime


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
