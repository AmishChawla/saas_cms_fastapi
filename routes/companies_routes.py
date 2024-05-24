import datetime
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter
from sqlalchemy.orm import Session, joinedload
from schemas import User, get_db, SessionLocal, Company
from methods import get_password_hash, verify_password, get_current_user, oauth2_scheme, \
    get_user_from_token
# from fastapi_cache.decorator import cache
# from fastapi_cache import FastAPICache
# from fastapi_cache.decorator import cache
# from fastapi_cache import FastAPICache



company_router = APIRouter()


########################################################################## COMPNIES ###########################################################################

# Endpoint to create new company
@company_router.post("/api/companies/create-company")
def create_company(name: str, location: str, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Create Company

    Endpoint: POST api/companies/create-company
    Description: Creates a new company with the provided name, location, and user ID.
    Parameters:
    name: Name of the company (string)
    location: Location of the company (string)
    Returns: The newly created company object.
    """

    current_user = get_user_from_token(token)
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Create the company
    company = Company(name=name, location=location, user_id=current_user.id, created_at=datetime.datetime.utcnow())
    db.add(company)
    db.commit()
    db.refresh(company)

    return {
        "id": company.id,
        "name": company.name,
        "location": company.location,
        "created_at": company.created_at,
        "user_id": company.user_id
    }


# Endpoint to remove a company by its ID
@company_router.delete("/api/companies/delete-company/{company_id}")
def delete_company(company_id: int, db: Session = Depends(get_db)):
    """
    Delete Company

    Endpoint: DELETE /companies/{company_id}
    Description: Deletes the company with the specified ID.
    Parameters:
    company_id: ID of the company to delete (integer)
    Returns: A message indicating the deletion was successful.
    """
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    db.delete(company)
    db.commit()
    return {"message": "Company deleted successfully"}


# Endpoint to update a company's information
@company_router.put("/api/companies/update-company/{company_id}")
def update_company(company_id: int, name: str = None, location: str = None, db: Session = Depends(get_db)):
    """
Update Company

Endpoint: PUT /companies/{company_id}
Description: Updates the information of the company with the specified ID.
Parameters:
company_id: ID of the company to update (integer)
name (optional): New name of the company (string)
location (optional): New location of the company (string)
Returns: The updated company object.
    """
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    if name:
        company.name = name
    if location:
        company.location = location
    db.commit()
    db.refresh(company)

    return company


# Endpoint to get information about a specific company
@company_router.get("/api/companies/{company_id}")
def get_company(company_id: int, db: Session = Depends(get_db)):
    """
    Get Company

Endpoint: GET /companies/{company_id}
Description: Retrieves information about the company with the specified ID.
Parameters:
company_id: ID of the company to retrieve (integer)
Returns: The company object containing its name, location, and associated user ID.
"""
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return company


# Endpoint to get the company of a user
@company_router.get("/api/user/company/")
def get_user_company(token: str = Depends(oauth2_scheme)):
    """
    Get company of the user
    :param db: Database session
    :param token: User token
    :return: Company details
    """
    db = SessionLocal()
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    company = db.query(Company).filter(Company.user_id == user.id).first()

    # If company is not found, raise HTTP exception
    if not company:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User has not registered a company")

    # Return the company details
    return company


# Endpoint to get all companies
@company_router.get("/api/companies/")
def get_all_companies(db: Session = Depends(get_db)):
    """
    Get All Companies

    Endpoint: GET /api/companies/
    Description: Retrieves all companies from the database.
    Returns: List of all companies.
    """

    companies = db.query(Company).all()
    return companies