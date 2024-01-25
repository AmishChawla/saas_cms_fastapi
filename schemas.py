

from sqlalchemy import Column, String, Integer, ForeignKey, LargeBinary, JSON, func, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from constants import DATABASE_URL
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
import databases
import secrets



Base = declarative_base()
engine = create_engine(DATABASE_URL)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
    token = Column(String, default="")
    created_datetime = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="active")

    resume_data = relationship("ResumeData", back_populates="user")
    password_resets = relationship("PasswordReset", back_populates="user")
    pdf_files = relationship("PDFFiles", back_populates="user")


class ResumeData(Base):
    __tablename__ = "resume_data"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    extracted_data = Column(JSON)
    csv_file = Column(LargeBinary)
    xml_file = Column(LargeBinary)
    upload_datetime = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="resume_data")


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, default=secrets.token_urlsafe)
    user_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="password_resets")


class PDFFiles(Base):
    __tablename__ = "pdf_files"

    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, nullable=False)
    file_data = Column(LargeBinary, nullable=False)
    upload_datetime = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship("User", back_populates="pdf_files")



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

