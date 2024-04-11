from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Form, APIRouter
from sqlalchemy.exc import IntegrityError
from typing import List
from sqlalchemy.orm import Session, joinedload
from schemas import User, get_db, Service, UserServices
from fastapi_cache.decorator import cache
from fastapi_cache import FastAPICache




services_router = APIRouter()


########################################################## SERVICES ###################################################################################################
@services_router.post("/api/services/create-service")
async def create_service(name: str, description: str, db: Session = Depends(get_db)):
    """
    Create a service

    Args:
        name (String): Name of the service
        description (String): Description of the service
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response giving details of the service.
    """
    try:
        new_service = Service(name=name, description=description)
        db.add(new_service)
        db.commit()
        db.refresh(new_service)
        FastAPICache.delete_url("/api/services/all-services")
        return new_service
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Service with this name already exists")


@services_router.delete("/api/services/delete-service/{service_id}")
async def delete_service(service_id: int, db: Session = Depends(get_db)):
    """
    Delete an existing service.

    Args:
        service_id (int): The ID of the service to be deleted..
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    service = db.query(Service).filter(Service.service_id == service_id).first()
    if service:
        db.delete(service)
        db.commit()
        FastAPICache.delete_url("/api/services/all-services")
        return {"message": "Service deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Service not found")


@services_router.post("/api/users/assign_services")
async def assign_services_to_user(user_id: int, service_ids: List[int], db: Session = Depends(get_db)):
    """
    Assign multiple services to a user.

    Args:
        user_id (int): The ID of the user.
        service_ids (List[int]): A list of service IDs to be assigned to the user.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    # Fetch the user from the database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Fetch services from the database based on service_ids
    services = db.query(Service).filter(Service.service_id.in_(service_ids)).all()

    if len(services) != len(service_ids):
        raise HTTPException(status_code=404, detail="Some services not found")

    # Clear existing user services
    db.query(UserServices).filter(UserServices.user_id == user_id).delete()

    # Assign services to the user
    for service_id in service_ids:
        user_service = UserServices(user_id=user_id, service_id=service_id)
        db.add(user_service)

    db.commit()
    FastAPICache.delete_url("/api/users/{user_id}/services")
    FastAPICache.delete_url("/api/admin/view-user/{user_id}")
    FastAPICache.delete_url("/api/user-profile")


    return {"message": "Services assigned to user successfully"}


@services_router.delete("/api/users/{user_id}/remove_service/{service_id}")
async def remove_service_from_user(user_id: int, service_id: int, db: Session = Depends(get_db)):
    """
    Remove a service from a user.

    Args:
        user_id (int): The ID of the user.
        service_id (int): The ID of the service to be removed from the user.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    user_service = db.query(UserServices).filter(UserServices.user_id == user_id,
                                                 UserServices.service_id == service_id).first()
    if user_service is None:
        raise HTTPException(status_code=404, detail="Service not found for this user")

    db.delete(user_service)
    db.commit()
    FastAPICache.delete_url("/api/users/{user_id}/services")
    FastAPICache.delete_url("/api/user-profile")

    return {"message": "Service removed from user successfully"}


@services_router.get("/api/services/all-services")
@cache()
async def get_all_services(db: Session = Depends(get_db)):
    """
    Get all available services.

    Args:
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        List[Service]: A list of all available services.
    """
    services = db.query(Service).all()
    return services


@services_router.get("/api/users/{user_id}/services")
@cache()
async def get_user_services(user_id: int, db: Session = Depends(get_db)):
    """
    Get all services associated with a specific user.

    Args:
        user_id (int): The ID of the user.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        List[Service]: A list of services associated with the user.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user.services


@services_router.put("/api/services/update-service/{service_id}")
async def update_service(service_id: int, service_data: dict, db: Session = Depends(get_db)):
    """
    Update an existing service.

    Args:
        service_id (int): The ID of the service to be updated.
        service_data (dict): The updated service data.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response indicating success or failure.
    """
    # Retrieve the service from the database
    service = db.query(Service).filter(Service.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    # Update the service attributes
    for key, value in service_data.items():
        setattr(service, key, value)

    # Commit the changes to the database
    db.commit()
    FastAPICache.delete_url("/api/services/all-services")
    FastAPICache.delete_url("/api/services/{service_id}")

    return {"message": "Service updated successfully"}


@services_router.get("/api/services/{service_id}")
@cache()
async def get_service(service_id: int, db: Session = Depends(get_db)):
    """
    Get information about a particular service by its ID.

    Args:
        service_id (int): The ID of the service to retrieve.
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A JSON response containing information about the service.
    """
    # Retrieve the service from the database
    service = db.query(Service).filter(Service.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    # Convert the service object to a dictionary
    service_info = {
        "service_id": service.service_id,
        "service_name": service.name,
        "service_description": service.description,
        # Add more attributes as needed
    }

    return service_info

