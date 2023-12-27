from sqlalchemy import Column, String, Integer, ForeignKey, LargeBinary, JSON, func, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from constants import DATABASE_URL

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

    resume_data = relationship("ResumeData", back_populates="user")


class ResumeData(Base):
    __tablename__ = "resume_data"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    extracted_data = Column(JSON)
    csv_file = Column(LargeBinary)
    xml_file = Column(LargeBinary)
    upload_datetime = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="resume_data")




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

