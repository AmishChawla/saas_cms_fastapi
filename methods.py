import os
import re
import tempfile
import uuid
from email.mime.text import MIMEText
from smtplib import SMTP_SSL, SMTP
from fastapi import HTTPException, Depends, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, List
from passlib.context import CryptContext
from sqlalchemy.orm import joinedload

import constants
import models
import schemas
from constants import SECRET_KEY, ALGORITHM, EMAIL, EMAIL_PASSWORD, FLASK_URL
from sqlalchemy.orm import Session

from models import TokenData, UserFiles
from resume_parser import extract_data

from schemas import User, get_db, SessionLocal, ResumeData, PasswordReset
from sqlalchemy.orm import class_mapper
import stripe

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
stripe.api_key = constants.STRIPE_API_KEY


def get_password_hash(password):
    return pwd_context.hash(password)


# Dependency to verify the password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception
    return token_data


def get_user_from_token(token: str):
    db = SessionLocal()

    user = db.query(User).filter(User.token == token).first()
    db.close()
    return user


def get_scrapper_user_from_token(token: str):
    db = SessionLocal()
    user = db.query(schemas.ScrapperUser).filter(schemas.ScrapperUser.token == token).first()
    db.close()
    return user



def update_user_password(user_id: int, new_password):
    hashed_password = pwd_context.hash(new_password)
    db = SessionLocal()

    # Update the user's hashed password in the database
    db.execute(
        User.__table__.update().
            where(User.id == user_id).
            values(hashed_password=hashed_password)
    )
    # Commit the changes to the database
    db.commit()


async def parse_resume(files: List[UploadFile] = File(...)):
    try:
        # Temporary directory to save uploaded files
        temp_dir = tempfile.mkdtemp()

        # Save each uploaded file to the temporary directory
        file_paths = []
        for file in files:
            file_path = os.path.join(temp_dir, file.filename)
            with open(file_path, "wb") as file_obj:
                print(f"parsersume {file.file}")
                file_obj.write(file.file.read())
            file_paths.append(file_path)

        # Call your resume parser function
        resume_data, csvfile_path, xmlfile_path = await extract_data(file_paths)
        print(resume_data, csvfile_path, xmlfile_path)
        return resume_data, csvfile_path, xmlfile_path

    except Exception as e:
        return HTTPException(status_code=500, detail=f"Error processing files: {str(e)}")
    finally:
        # Clean up: Remove the temporary directory and its contents
        for file_path in file_paths:
            os.remove(file_path)
        os.rmdir(temp_dir)


def row_to_dict(row):
    data = {}
    for column in class_mapper(row.__class__).mapped_table.c:
        data[column.name] = getattr(row, column.name)
    return data


def get_user_files(user_id: int):
    db = SessionLocal()
    user_csv_files = db.query(ResumeData.csv_file).filter(ResumeData.user_id == user_id).filter(
        ResumeData.csv_file.isnot(None)).all()

    # Extract CSV file paths from the result
    csv_files = [str(file) for file in user_csv_files]

    return csv_files


def create_password_reset_token(email: str, expires_delta: timedelta):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if user:
        db_password_reset = PasswordReset(user_id=user.id)
        db.add(db_password_reset)
        db.commit()
        db.refresh(db_password_reset)

        token_data = {
            "sub": str(db_password_reset.id),
            "email": email,
        }
        access_token_expires = timedelta(minutes=expires_delta)
        access_token = create_access_token(
            data={"sub": str(db_password_reset.id), "email": email},
            expires_delta=access_token_expires,
        )
        return access_token


def admin_send_email(recipient_emails: List[str], message: str, subject: str, db_session: Session):
    print(f"trying to send email")
    try:

        smtp_settings = db_session.query(schemas.SMTPSettings).filter(schemas.SMTPSettings.id == 2).first()

        if not smtp_settings:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="SMTP settings not found for user",
            )
        print("got smtp settings for admin")
        msg = MIMEText(message, "html")
        msg['Subject'] = subject
        msg['From'] = smtp_settings.sender_email
        # to_mail_list = ", ".join(recipient_emails)
        # print(to_mail_list)
        msg['To'] = recipient_emails[0]


        # Connect to the email server and start TLS
        server = SMTP(smtp_settings.smtp_server, smtp_settings.smtp_port)
        server.starttls()
        print("tls started")
        # Login to the email server
        server.login(smtp_settings.sender_email, smtp_settings.smtp_password)
        print("logged in ")
        server.sendmail(smtp_settings.sender_email, recipient_emails, msg.as_string())
        print("mail sent")

        server.quit()
        print("quit server")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def send_email(recipient_emails: List[str], message: str, subject: str, db_session: Session, role: str, user_id: str):
    print(f"trying to send email")
    try:
        smtp_settings = db_session.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.id == 2).first() if role == 'admin' else db_session.query(schemas.SMTPSettings).filter(
            schemas.SMTPSettings.user_id == user_id).first()

        if not smtp_settings:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="SMTP settings not found for user",
            )

        # message_template = f"""From: {smtp_settings.sender_email}\n
        #                     Subject: {subject}\n
        #                     {message}"""
        # Prepare the email message
        msg = MIMEText(message, "html")
        msg['Subject'] = subject
        msg['From'] = smtp_settings.sender_email
        msg['To'] = recipient_emails[0]
        bcc_mail_list = ", ".join(recipient_emails)
        msg['Bcc'] = bcc_mail_list
        # to_mail_list = ", ".join(recipient_emails)
        # msg['To'] = to_mail_list


        # Connect to the email server and start TLS
        server = SMTP(smtp_settings.smtp_server, smtp_settings.smtp_port)
        server.starttls()

        # Login to the email server
        server.login(smtp_settings.sender_email, smtp_settings.smtp_password)
        server.sendmail(smtp_settings.sender_email, recipient_emails, msg.as_string())

        # for recipient_email in recipient_emails:
        #     msg['To'] = recipient_email
        #
        #     # Send the email
        #     server.sendmail(smtp_settings.sender_email, recipient_email, msg.as_string())

        server.quit()

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not send email + {e}",
        )


def send_password_reset_email(email: str, reset_token, db_session: Session):
    print(f"tryng to send password reset email")

    message = f"""<p>Click the following link to reset your password: <a href='{FLASK_URL}/reset-password/{reset_token}'>Reset Password</a></p> """

    try:
        print('before admin send email')
        admin_send_email(recipient_emails=[email], message=message, subject='Password Reset', db_session=db_session)
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not send password reset email",
        )


def is_service_allowed(user_id: int):
    """
    Check if a service is allowed for a user.
    :param user_id: (int) ID of the user
    :return: True or False
    """
    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    print('here')
    if user is None:
        return False
    print('here')
    print(user.stripe_customer_id)
    if user.stripe_customer_id is None or '':
        subscriptions = user.subscriptions
        print(len(subscriptions))
        if subscriptions is []:
            return False
        else:
            for subscription in subscriptions:
                if subscription.status == 'active':
                    return True
                else:
                    return False



    subscription = db.query(schemas.Subscription).filter(
        schemas.Subscription.stripe_customer_id == user.stripe_customer_id).first()
    if subscription is None:
        return False

    try:
        stripe_subscription = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
        if stripe_subscription.status == 'active':
            return True
        return False
    except stripe.error.StripeError as e:
        print(f"Stripe Error: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def get_all_resume_data(db: Session):
    return db.query(schemas.ResumeData).all()


def save_profile_picture(file: UploadFile) -> str:
    # Generate a unique identifier
    unique_id = uuid.uuid4().hex
    # Extract file extension
    file_ext = os.path.splitext(file.filename)[1]
    # Construct new filename with unique identifier
    new_filename = f"profile_picture_{unique_id}{file_ext}"
    # Define file location
    file_location = f"profile_pictures/{new_filename}"
    # Save the file
    with open(file_location, "wb") as buffer:
        buffer.write(file.file.read())

    return file_location


##################################################### STRIPE ##################################################################

def create_stripe_product_and_price(plan):
    product = stripe.Product.create(
        name=plan.plan_type_name,
        description=plan.plan_details,
    )
    # Check if the plan is a demo plan
    price = stripe.Price.create(
        product=product.id,
        unit_amount=plan.fees * 100,  # for USD
        currency='usd',
        recurring={
            'interval': "month",
            "interval_count": int(plan.time_period)
        },
    )

    return product, price


def delete_stripe_product_and_price(stripe_price_id, stripe_product_id):
    stripe.Price.delete(stripe_price_id)
    # Delete the Stripe product
    stripe.Product.delete(stripe_product_id)


def update_subscription_status_in_db(db: Session, subscription_id: str, new_status: str, plan_id: int):
    # Retrieve the subscription from the database
    subscription = db.query(schemas.Subscription).filter(
        schemas.Subscription.stripe_subscription_id == subscription_id).first()

    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")

    # Update the subscription status
    subscription.plan_id = plan_id
    subscription.status = new_status
    db.commit()
    db.refresh(subscription)

    return subscription


################### CURRENT PLAN DETAILS ##################################
def get_current_plan_details(stripe_subscription_id: str, db: Session):
    """
    Retrieve information about the current plan and subscription details
    based on the provided Stripe subscription ID.

    Args:
        db (Session): Database session.
        stripe_subscription_id (str): Stripe subscription ID.

    Returns:
        dict: Dictionary containing plan and subscription details.
    """
    stripe_subscription = stripe.Subscription.retrieve(stripe_subscription_id)
    subscription = db.query(schemas.Subscription).filter(
        schemas.Subscription.stripe_subscription_id == stripe_subscription_id).first()

    next_billing_date = datetime.fromtimestamp(stripe_subscription["current_period_end"]).strftime('%d %B %Y')

    if subscription and stripe_subscription:
        plan = subscription.plan

        subscription_details = {
            "stripe_subscription_id": stripe_subscription_id,
            "plan_name": plan.plan_type_name,
            "status": stripe_subscription["status"],
            "next_billing_date": next_billing_date,
            "cancel_at_period_end": stripe_subscription["cancel_at_period_end"],
            # Assuming next billing date is calculated as the last billing date plus the subscription period
            "created_at": subscription.created_at,
            "updated_at": subscription.updated_at
        }
        return subscription_details
    else:
        return None


def generate_slug(title: str) -> str:
    """
    Generates a slug from the given title.
    Replaces spaces with hyphens and converts to lowercase.
    """
    slug = re.sub(r'\s+', '-', title.lower())
    return slug.strip('-')


def ensure_unique_post_slug(slug: str, user_id: int, db_session) -> str:
    """
    Ensures the slug is unique for the given user.
    Appends numbers to the slug if necessary.
    """
    existing_slugs = db_session.query(schemas.Post.slug).filter(schemas.Post.user_id == user_id).all()
    existing_slugs = [slug[0] for slug in existing_slugs]

    if slug in existing_slugs:
        count = 1
        while f"{slug}-{count}" in existing_slugs:
            count += 1

        return f"{slug}-{count}"
    else:
        return slug

def ensure_unique_page_slug(slug: str, user_id: int, db_session) -> str:
    """
    Ensures the slug is unique for the given user.
    Appends numbers to the slug if necessary.
    """
    existing_slugs = db_session.query(schemas.Page.slug).filter(schemas.Page.user_id == user_id).all()
    existing_slugs = [slug[0] for slug in existing_slugs]
    print(existing_slugs)
    if slug in existing_slugs:
        count = 1
        while f"{slug}-{count}" in existing_slugs:
            count += 1
            print(f"{slug}-{count}")
        return f"{slug}-{count}"
    else:
        return slug


def increment_category_count(db: Session, category_id: int):
    category = db.query(schemas.Category).filter(schemas.Category.id == category_id).first()
    if category:
        category.count += 1
        db.commit()

def increment_post_views(db: Session, post_id: int):
    db.execute("UPDATE posts SET post_views = post_views + 1 WHERE id = :post_id", {"post_id": post_id})
    db.commit()


def increment_page_views(db: Session, page_id: int):
    db.execute("UPDATE pages SET page_views = page_views + 1 WHERE id = :page_id", {"page_id": page_id})
    db.commit()


################################## ORDER HISTORY #############################

def order_history(user_id: int, db: Session):
    """
    Get purchase history of the user
    """
    subscriptions = db.query(schemas.Subscription).filter(schemas.Subscription.user_id == user_id). \
        options(joinedload(schemas.Subscription.plan)).all()
    return subscriptions
