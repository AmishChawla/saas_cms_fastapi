from typing import Union, List, Optional
from pydantic import BaseModel, validator
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
    security_group: int


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

class PostCreate(BaseModel):
    title: str
    content: str
    category_id: int
    subcategory_id: int
    status: str
    tags: List[str]

class PageCreate(BaseModel):
    title: str
    content: str
    status: str

class CategoryCreate(BaseModel):
    category: str

class CommentCreate(BaseModel):
    post_id: int
    reply_id: Optional[int] = None
    comment: str

class CommentSettingsUpdate(BaseModel):
    notify_linked_blogs: bool = False
    allow_trackbacks: bool = False
    allow_comments: bool = True
    comment_author_info: bool = False
    registered_users_comment: bool = False
    auto_close_comments: int = 14
    show_comment_cookies: bool = False
    enable_threaded_comments: bool = False
    email_new_comment: bool = False
    email_held_moderation: bool = False
    email_new_subscription: bool = False
    comment_approval: str = 'manual'


class AddLike(BaseModel):
    post_id: int
    comment_id: int

class SubcategoryCreate(BaseModel):
    subcategory: str
    category_id: int

class TagBase(BaseModel):
    tag: str

class TagCreate(TagBase):
    pass

class TagUpdate(TagBase):
    pass

class TagInDB(TagBase):
    id: int


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



class UserThemeCreate(BaseModel):

    theme_id: int  # New theme_id field
    theme_name: str
    background_image: Optional[str] = None
    background_color: Optional[str] = None
    header_color: Optional[str] = None
    site_title: Optional[str] = None
    site_subtitle: Optional[str] = None
    home_link: Optional[str] = None
    heading: Optional[str] = None
    description: Optional[str] = None
    footer_heading: Optional[str] = None
    footer_items: Optional[List[str]] = None
    facebook: Optional[str] = None
    twitter: Optional[str] = None
    youtube: Optional[str] = None
    pinterest: Optional[str] = None
    instagram: Optional[str] = None
    gmail: Optional[str] = None


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


######################################################## Plans ########################################################################
class PlanBase(BaseModel):
    plan_type_name: str
    time_period: str
    fees: int
    num_resume_parse: str  # Change to string type
    plan_details: str

    @validator('num_resume_parse')
    def validate_num_resume_parse(cls, value):
        if value.lower() != 'unlimited':
            try:
                int(value)
            except ValueError:
                raise ValueError("num_resume_parse must be 'unlimited' or a valid integer")
        return value


class PlanResponse(PlanBase):
    id: int
    stripe_product_id: str  # New field for Stripe Product ID
    stripe_price_id: str


class EmailTemplateCreate(BaseModel):
    name: str
    subject: str
    body: str

class Mail(BaseModel):
    to: str
    subject: str
    body: str


class NewsLetterSubscription(BaseModel):
    subscriber_name: str
    subscriber_email: str
    username: str


class UnsubscribeNewsletter(BaseModel):
    subscriber_email: str
    username: str

class FormData(BaseModel):
    form_name: str
    form_html: str
    responses: Optional[dict] = None
    unique_id: str

class MenuCreate(BaseModel):
    name: str


