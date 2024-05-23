
from fastapi import HTTPException, Depends, status
import methods
import models
import schemas
from sqlalchemy.orm import Session


def create_email_settings(smtp_settings: models.SMTPSettingsBase, token: str,
                                db: Session):
    """
    Create new SMTP settings these are used to send and recieve emails.

    :param smtp_settings: New SMTP Settings of email
    :param token: Auth token to verify user
    :param db: db session to perform crud
    :return: created smtp settings
    """

    # Check if the user is an admin
    user = methods.get_user_from_token(token)
    if user.role == "admin":
        # Check if the admin user already has email settings
        existing_smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.id == 2).first()  # ID 2 is where admin smpt settings are stored.
        if existing_smtp_settings:
            raise HTTPException(status_code=400, detail="Admin email settings already exist")

        # Create new email settings
        db_smtp_settings = schemas.SMTPSettings(
            user_id=user.id,
            smtp_server=smtp_settings.smtp_server,
            smtp_port=smtp_settings.smtp_port,
            sender_email=smtp_settings.sender_email,
            smtp_username=smtp_settings.smtp_username,
            smtp_password=smtp_settings.smtp_password
        )
        db.add(db_smtp_settings)
        db.commit()
        db.refresh(db_smtp_settings)
    if user.role == "user":
        # Check if the admin user already has email settings
        existing_smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.user_id == user.id).first()  # Sort based on user id
        if existing_smtp_settings:
            raise HTTPException(status_code=400, detail="User email settings already exist")

        # Create new email settings
        db_smtp_settings = schemas.SMTPSettings(
            user_id=user.id,
            smtp_server=smtp_settings.smtp_server,
            smtp_port=smtp_settings.smtp_port,
            sender_email=smtp_settings.sender_email,
            smtp_username=smtp_settings.smtp_username,
            smtp_password=smtp_settings.smtp_password
        )
        db.add(db_smtp_settings)
        db.commit()
        db.refresh(db_smtp_settings)

    return db_smtp_settings


def get_smtp_settings(token: str ,db: Session):
    """
    Get SMTP details of user from db

    :param token: Auth token to verify user
    :param db: session to read smtp info from db
    :return: Returns SMTP details of the user from the db
    """
    # Fetch the user based on the provided token
    user = methods.get_user_from_token(token)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    elif user.role == 'admin':
        # Fetch the SMTP settings associated with the user
        smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.id  == 2).first()
        if smtp_settings is None:
            raise HTTPException(status_code=404, detail="SMTP settings not found")

    elif user.role == 'user':
        # Fetch the SMTP settings associated with the user
        smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.user_id == user.id).first()
        if smtp_settings is None:
            raise HTTPException(status_code=404, detail="SMTP settings not found")
    return smtp_settings


def update_admin_email_settings(smtp_settings_update: models.SMTPSettingsBase, token: str,
                                db: Session):
    """
    Update SMTP details of any user

    :param smtp_settings_update: New details
    :param token: Authenticate users
    :param db: Session to update details in db
    :return: New and updated SMTP details
    """
    # Fetch the user based on the provided token
    user = methods.get_user_from_token(token)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    elif user.role == "admin":
        # Fetch the existing SMTP settings associated with the user
        existing_smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.id == 2).first()  # ID 2 is where admin smpt settings are stored.
        if existing_smtp_settings is None:
            raise HTTPException(status_code=404, detail="SMTP settings not found")

        # Update the SMTP settings

        existing_smtp_settings.smtp_server = smtp_settings_update.smtp_server
        existing_smtp_settings.smtp_port = smtp_settings_update.smtp_port
        existing_smtp_settings.smtp_username = smtp_settings_update.smtp_username
        existing_smtp_settings.smtp_password = smtp_settings_update.smtp_password
        existing_smtp_settings.sender_email = smtp_settings_update.sender_email

        db.commit()
        db.refresh(existing_smtp_settings)

    elif user.role == "user":
        # Fetch the existing SMTP settings associated with the user
        existing_smtp_settings = db.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.user_id == user.id).first()
        if existing_smtp_settings is None:
            raise HTTPException(status_code=404, detail="SMTP settings not found")

        # Update the SMTP settings

        existing_smtp_settings.smtp_server = smtp_settings_update.smtp_server
        existing_smtp_settings.smtp_port = smtp_settings_update.smtp_port
        existing_smtp_settings.smtp_username = smtp_settings_update.smtp_username
        existing_smtp_settings.smtp_password = smtp_settings_update.smtp_password
        existing_smtp_settings.sender_email = smtp_settings_update.sender_email

        db.commit()
        db.refresh(existing_smtp_settings)

    return existing_smtp_settings


