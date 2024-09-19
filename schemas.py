import datetime

from sqlalchemy import Column, String, Integer, ForeignKey, LargeBinary, JSON, func, DateTime, ARRAY, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from constants import DATABASE_URL
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
import databases
import secrets
from sqlalchemy.engine.reflection import Inspector




Base = declarative_base()
engine = create_engine(DATABASE_URL)


class SMTPSettings(Base):
    __tablename__ = "smtp_settings"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    smtp_server = Column(String, nullable=True)
    smtp_port = Column(Integer, nullable=True)
    smtp_username = Column(String, nullable=True)
    smtp_password = Column(String, nullable=True)
    sender_email = Column(String, nullable=True)

    user = relationship("User", back_populates="smtp_settings")


class EmailTemplate(Base):
    __tablename__ = 'email_templates'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    name = Column(String(100), nullable=False)
    subject = Column(String(200), nullable=False)
    body = Column(Text, nullable=False)

    def __repr__(self):
        return f'<EmailTemplate(name={self.name}, user_id={self.user_id})>'


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
    token = Column(String, default="")
    stripe_customer_id = Column(String, unique=True)
    created_datetime = Column(DateTime(timezone=True), server_default=func.now())
    profile_picture = Column(String, nullable=True)
    status = Column(String, default="active", index=True)
    group_id = Column(Integer, ForeignKey('groups.id'))

    resume_data = relationship("ResumeData", back_populates="user")
    resume_collection = relationship("ResumeCollection", back_populates="user")
    user_chats = relationship("UserChats", back_populates="user")
    password_resets = relationship("PasswordReset", back_populates="user")
    services = relationship("Service", secondary="user_services")
    company = relationship("Company", back_populates="user")
    smtp_settings = relationship("SMTPSettings", uselist=False, back_populates="user")
    subscriptions = relationship("Subscription", back_populates="user")
    posts = relationship("Post", back_populates="user")
    categories = relationship("Category", back_populates="user")
    subcategories = relationship("SubCategory", back_populates="user")
    favorites = relationship("TagUser", back_populates="user")
    commentslikes = relationship("Commentlike", back_populates="user")
    comments = relationship("Comment", back_populates="user")
    media = relationship("Media", back_populates="user")
    feedbacks = relationship('Feedback', back_populates='user')
    newsletter_subscriptions = relationship('NewsLetterSubscription', back_populates='user')
    pages = relationship("Page", back_populates="user")
    settings = relationship("UserSetting", back_populates="user", uselist=False)
    selected_media = relationship("SelectedMedia", back_populates="user")

    themes = relationship('UserTheme', back_populates='user')

    created_forms = relationship("UserForms", back_populates="user")
    groups = relationship("Group", back_populates="user")



class Service(Base):

    __tablename__ = 'services'

    service_id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(Text)

    users = relationship("User", secondary="user_services")

class UserServices(Base):
    __tablename__ = 'user_services'

    user_service_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    service_id = Column(Integer, ForeignKey('services.service_id'))


class ResumeData(Base):
    __tablename__ = "resume_data"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    extracted_data = Column(JSON)
    csv_file = Column(LargeBinary)
    xml_file = Column(LargeBinary)
    upload_datetime = Column(DateTime(timezone=True), server_default=func.now())
    # pdf_resumes = Column(ARRAY(LargeBinary))

    user = relationship("User", back_populates="resume_data")

class Plan(Base):
    __tablename__ = 'plans'

    id = Column(Integer, primary_key=True)
    plan_type_name = Column(String)
    time_period = Column(String)   #months
    fees = Column(Integer)
    num_resume_parse = Column(String)
    plan_details = Column(String)
    stripe_product_id = Column(String) # New field for Stripe Product ID
    stripe_price_id = Column(String)

    subscriptions = relationship("Subscription", back_populates="plan")

class Subscription(Base):
    __tablename__ = 'subscriptions'

    id = Column(Integer, primary_key=True)
    stripe_subscription_id = Column(String, unique=True)
    stripe_customer_id = Column(String)
    plan_id = Column(Integer, ForeignKey('plans.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    status = Column(String) # e.g., 'active', 'past_due', 'canceled', etc.
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = relationship("User", back_populates="subscriptions")
    plan = relationship('Plan', back_populates='subscriptions')


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, default=secrets.token_urlsafe)
    user_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="password_resets")


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    location = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))

    user = relationship("User", back_populates="company")

class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    author_name = Column(String, nullable=False)
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    subcategory_id = Column(Integer, ForeignKey('subcategories.id'))
    status = Column(String, default="published", index=True)
    slug = Column(String, unique=True, index=True, nullable=False)
    post_views = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="posts")
    category = relationship("Category", back_populates="posts")
    subcategory = relationship("SubCategory", back_populates="posts")
    comment = relationship("Comment", back_populates="posts")
    tags = relationship("Tag", secondary="tag_post", back_populates="posts")
    commentslikes = relationship("Commentlike", back_populates="posts")
    selected_media = relationship("SelectedMedia", back_populates="post")


class Page(Base):
    __tablename__ = "pages"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    author_name = Column(String, nullable=False)
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    status = Column(String, default="published", index=True)
    slug = Column(String, index=True, nullable=False)
    page_views = Column(Integer, default=0)
    display_in_nav = Column(String, default="no")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="pages")



class Category(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey('users.id'))
    count = Column(Integer, default=0)

    user = relationship("User", back_populates="categories")
    posts = relationship("Post", back_populates="category")

class SubCategory(Base):
    __tablename__ = "subcategories"

    id = Column(Integer, primary_key=True, index=True)
    subcategory = Column(String, nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship("User", back_populates="subcategories")
    posts = relationship("Post", back_populates="subcategory")


class Tag(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, index=True)
    tag = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Corrected relationship names for clarity
    favorited_by_users = relationship("TagUser", back_populates="tag")
    posts = relationship(
        "Post",
        secondary="tag_post",
        back_populates="tags"  # Corrected to match the relationship name on the Post model
    )


class TagUser(Base):
    __tablename__ = "tag_user"

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    tag_id = Column(Integer, ForeignKey('tags.id'), primary_key=True)
    post_count = Column(Integer, default=0)

    user = relationship("User", back_populates="favorites")
    tag = relationship("Tag", back_populates="favorited_by_users")


class TagPost(Base):
    __tablename__ = "tag_post"

    post_id = Column(Integer, ForeignKey("posts.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)

class Media(Base):
    __tablename__ = "media"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_url = Column(String, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship("User", back_populates="media")
    selected_media = relationship("SelectedMedia", back_populates="media")


class SelectedMedia(Base):
    __tablename__ = "selected_media"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    media_id = Column(Integer, ForeignKey('media.id'), nullable=False)
    post_id = Column(Integer, ForeignKey('posts.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="selected_media")
    media = relationship("Media", back_populates="selected_media")
    post = relationship("Post", back_populates="selected_media")


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    reply_id = Column(Integer, ForeignKey('comments.id'))
    post_id = Column(Integer, ForeignKey('posts.id'), nullable=False)
    comment = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    like = Column(Integer, default=0, nullable=False)
    active = Column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="comments")
    replies = relationship("Comment", backref="parent_comment", remote_side=[id])
    posts = relationship("Post", back_populates="comment")
    commentslikes = relationship("Commentlike", back_populates="comments")


class Commentlike(Base):
    __tablename__ = "commentslikes"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    post_id = Column(Integer, ForeignKey('posts.id'), nullable=False)
    comment_id = Column(Integer, ForeignKey('comments.id'), nullable=False)

    user = relationship("User", back_populates="commentslikes")
    posts = relationship("Post", back_populates="commentslikes")
    comments = relationship("Comment", back_populates="commentslikes")


class Feedback(Base):
    __tablename__ = 'feedback'

    id = Column(Integer, primary_key=True)
    firstname = Column(String, nullable=False)
    lastname = Column(String, nullable=False)
    email = Column(String, nullable=False)
    message = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


    # Relationship to User
    user = relationship('User', back_populates='feedbacks')


class UserTheme(Base):
    __tablename__ = 'user_themes'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    theme_id = Column(Integer, nullable=False)
    theme_name = Column(String, nullable=False)
    background_image = Column(String)
    background_color = Column(String)
    header_color = Column(String)
    site_title = Column(String)
    site_subtitle = Column(String)
    home_link = Column(String)
    heading = Column(String)
    description = Column(String)
    footer_heading = Column(String)
    footer_items = Column(String)
    facebook = Column(String)
    twitter = Column(String)
    youtube = Column(String)
    pinterest = Column(String)
    instagram = Column(String)
    gmail = Column(String)

    # Relationship to User
    user = relationship('User', back_populates='themes')


######################################################### NEWSLETTER ######################################################################


class NewsLetterSubscription(Base):
    __tablename__ = 'newsletter_subscriptions'
    id = Column(Integer, primary_key=True)
    subscriber_name = Column(String)
    subscriber_email = Column(String)
    status = Column(String, default="active", index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship('User', back_populates='newsletter_subscriptions')


class UserSetting(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    notify_linked_blogs = Column(Boolean, default=False, nullable=False)
    allow_trackbacks = Column(Boolean, default=False, nullable=False)
    allow_comments = Column(Boolean, default=True, nullable=False)
    comment_author_info = Column(Boolean, default=False, nullable=False)
    registered_users_comment = Column(Boolean, default=False, nullable=False)
    auto_close_comments = Column(Integer, default=14, nullable=False)
    show_comment_cookies = Column(Boolean, default=False, nullable=False)
    enable_threaded_comments = Column(Boolean, default=False, nullable=False)
    email_new_comment = Column(Boolean, default=False, nullable=False)
    email_held_moderation = Column(Boolean, default=False, nullable=False)
    email_new_subscription = Column(Boolean, default=False, nullable=False)
    comment_approval = Column(String, default='manual', nullable=False)

    user = relationship("User", back_populates="settings")


class UserForms(Base):
    __tablename__ = "user_forms"

    id = Column(Integer, primary_key=True, index=True)
    unique_id = Column(String, nullable=False, unique=True)
    form_name = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    form_html = Column(Text, nullable=False)  # Storing the form in HTML format
    responses = Column(JSON, nullable=True)  # Storing the responses in JSON format
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="created_forms")


class ResumeCollection(Base):
    __tablename__ = "resume_collection"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    extracted_data = Column(JSON)
    upload_datetime = Column(DateTime(timezone=True), server_default=func.now())
    # pdf_resumes = Column(ARRAY(LargeBinary))

    user = relationship("User", back_populates="resume_collection")

class UserChats(Base):
    __tablename__ = "user_chats"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    messages = Column(JSON)
    upload_datetime = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="user_chats")


class Group(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    permissions = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="groups")
    scrapper_user = relationship("ScrapperUser", back_populates="groups")


class ScrapperUser(Base):
    __tablename__ = "scrapper_users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String)
    hashed_password = Column(String)
    role = Column(String, default="user")
    token = Column(String, default="")
    created_datetime = Column(DateTime(timezone=True), server_default=func.now())
    profile_picture = Column(String, nullable=True)
    status = Column(String, default="active", index=True)
    group_id = Column(Integer, ForeignKey('groups.id'))

    groups = relationship("Group", back_populates="scrapper_user")




class ScrappedJobs(Base):
    __tablename__ = "scrapped_jobs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    job_link = Column(String)
    state = Column(String)
    description = Column(Text)
    company = Column(String)
    seniority_level = Column(String)
    job_type = Column(String)
    job_function = Column(String)
    industry = Column(String)
    applicants = Column(Integer)
    apply_url = Column(String)
    posted_date = Column(DateTime)







# Create all tables defined in the metadata
Base.metadata.create_all(bind=engine)
print("Tables created successfully.")


# Create a sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

