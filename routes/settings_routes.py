from typing import Optional

from fastapi import HTTPException, Depends, status, APIRouter
from sqlalchemy.orm import Session, joinedload

from crud import smtp_crud
import methods
import models
import schemas
from schemas import get_db, SessionLocal
from methods import oauth2_scheme, get_user_from_token
import stripe
# from fastapi_cache.decorator import cache
# from fastapi_cache import FastAPICache


email_settings_router = APIRouter()
plan_settings_router = APIRouter()
subscription_router = APIRouter()


############################################### EMAIL SETTINGS ##############################################
@email_settings_router.post("/api/admin/email_settings/", response_model=models.SMTPSettings)
def create_admin_email_settings(smtp_settings: models.SMTPSettingsBase, token: str = Depends(oauth2_scheme),
                                db: Session = Depends(get_db)):
    db_smtp_settings = smtp_crud.create_email_settings(smtp_settings=smtp_settings, token=token, db=db)
    return db_smtp_settings


# Endpoint to get SMTP settings for admin
@email_settings_router.get("/api/smtp_settings/", response_model=models.SMTPSettings)
def get_smtp_settings(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    smtp_settings = smtp_crud.get_smtp_settings(token=token, db=db)
    return smtp_settings


# Update email settings
@email_settings_router.put("/api/admin/update-email-settings/", response_model=models.SMTPSettings)
def update_admin_email_settings(smtp_settings_update: models.SMTPSettingsBase, token: str = Depends(oauth2_scheme),
                                db: Session = Depends(get_db)):
    new_smtp_settings = smtp_crud.update_admin_email_settings(token=token, smtp_settings_update=smtp_settings_update, db=db)
    return new_smtp_settings


###################################################### PLAN SETTINGS #############################################################

@plan_settings_router.post("/api/plans/create-plan")
def create_plan(plan: models.PlanBase):
    db = SessionLocal()
    product, price = methods.create_stripe_product_and_price(plan)
    db_plan = schemas.Plan(
        plan_type_name=plan.plan_type_name,
        time_period=plan.time_period,
        fees=plan.fees,
        num_resume_parse=plan.num_resume_parse,
        plan_details=plan.plan_details,
        stripe_product_id=product.id,  # New field for Stripe Product ID
        stripe_price_id=price.id,

    )
    db.add(db_plan)
    db.commit()
    db.refresh(db_plan)
    db.close()
    return db_plan


@plan_settings_router.get("/api/plans/")
async def get_all_plans(db: Session = Depends(get_db)):
    try:
        plans = db.query(schemas.Plan).all()
        return plans
    except Exception as e:
        # Custom error message including the reason for the error
        error_message = f"Internal Server Error: {str(e)}"
        raise HTTPException(status_code=500, detail=error_message)


@plan_settings_router.get("/api/plans/{plan_id}")
def get_plan(plan_id: int):
    try:
        db = SessionLocal()
        plan = db.query(schemas.Plan).filter(schemas.Plan.id == plan_id).first()
        db.close()
        if plan is None:
            raise HTTPException(status_code=404, detail="Plan not found")
        return plan
    except Exception as e:
        # Custom error message including the reason for the error
        error_message = f"Internal Server Error: {str(e)}"
        raise HTTPException(status_code=500, detail=error_message)


@plan_settings_router.put("/api/plans/update-plan/{plan_id}")
def update_plan(plan_id: int, plan: models.PlanBase):
    db = SessionLocal()
    db_plan = db.query(schemas.Plan).filter(schemas.Plan.id == plan_id).first()
    if db_plan is None:
        db.close()
        raise HTTPException(status_code=404, detail="Plan not found")

    methods.delete_stripe_product_and_price(stripe_product_id=db_plan.stripe_product_id,
                                            stripe_price_id=db_plan.stripe_price_id)
    product, price = methods.create_stripe_product_and_price(plan)

    db_plan.plan_type_name = plan.plan_type_name
    db_plan.time_period = plan.time_period
    db_plan.fees = plan.fees
    db_plan.num_resume_parse = plan.num_resume_parse
    db_plan.plan_details = plan.plan_details
    db_plan.stripe_product_id = product.id
    db_plan.stripe_price_id = price.id

    db.commit()
    db.refresh(db_plan)
    db.commit()
    db.refresh(db_plan)
    db.close()
    return db_plan


@plan_settings_router.delete("/api/plans/delete-plan/{plan_id}")
def delete_plan(plan_id: int):
    db = SessionLocal()
    db_plan = db.query(schemas.Plan).filter(schemas.Plan.id == plan_id).first()
    if db_plan is None:
        db.close()
        raise HTTPException(status_code=404, detail="Plan not found")
    methods.delete_stripe_product_and_price(stripe_price_id=db_plan.stripe_price_id,
                                            stripe_product_id=db_plan.strpe_product_id)
    db.delete(db_plan)
    db.commit()
    db.close()
    return {"message": "Plan deleted successfully"}


################################################# SUBSCRIPTIONS #######################################################


@subscription_router.post("/api/subscriptions/create-subscription")
def create_subscription(
        plan_id: int,
        stripe_token: Optional[str] = None,
        db: Session = Depends(get_db),
        token: str = Depends(oauth2_scheme)
):
    """
    Create new Subscription
    """
    # Retrieve the user and plan from the database
    user = get_user_from_token(token)
    plan = db.query(schemas.Plan).filter(schemas.Plan.id == plan_id).first()

    if not user or not plan:
        raise HTTPException(status_code=404, detail="User or plan not found")

    if plan.fees == 0:
        existing_subscription = db.query(schemas.Subscription).filter_by(user_id=user.id, plan_id=plan_id).first()
        if existing_subscription:
            raise HTTPException(status_code=400, detail="Demo plan already used")

        # Directly create a demo subscription without Stripe
        db_subscription = schemas.Subscription(
            stripe_subscription_id=None,  # No Stripe subscription ID for demo plan
            stripe_customer_id=None,  # No Stripe customer ID for demo plan
            plan_id=plan_id,
            user_id=user.id,
            status="active",  # Mark as active since it's a demo plan
        )
        db.add(db_subscription)
        db.commit()
        db.refresh(db_subscription)

        return {"message": "Demo subscription successful", "subscription": db_subscription}

    try:
        # Check if the user already has a Stripe customer ID
        if not user.stripe_customer_id:
            # Create a new Stripe customer
            customer = stripe.Customer.create(email=user.email)
            user.stripe_customer_id = customer.id
            # Update the user's stripe_customer_id in the database using raw SQL
            update_query = """
                UPDATE users 
                SET stripe_customer_id = :customer_id 
                WHERE id = :user_id
            """
            db.execute(update_query, {"customer_id": customer.id, "user_id": user.id})
            db.commit()

            print('Updated user stripe_customer_id')

        if stripe_token:
            payment_method = stripe.PaymentMethod.create(
                type="card",
                card={
                    "token": stripe_token
                }
            )
            stripe.PaymentMethod.attach(
                payment_method.id,
                customer=user.stripe_customer_id,
            )

            # Set the attached Payment Method as the default payment method for the customer
            stripe.Customer.modify(
                user.stripe_customer_id,
                invoice_settings={
                    'default_payment_method': payment_method.id
                }
            )
        # Create a subscription for the user using the Stripe Price ID
        subscription = stripe.Subscription.create(
            customer=user.stripe_customer_id,
            items=[{'price': plan.stripe_price_id}],
            expand=['latest_invoice.payment_intent'],
        )

        # Create a new subscription record in the database and associate it with the user
        db_subscription = schemas.Subscription(
            stripe_subscription_id=subscription.id,
            stripe_customer_id=user.stripe_customer_id,
            plan_id=plan_id,
            user_id=user.id,
            status=subscription.status,
        )
        db.add(db_subscription)
        db.commit()
        db.refresh(db_subscription)

        return {"message": "Subscription successful", "subscription": subscription}

    except stripe.error.StripeError as e:
        # Handle Stripe API errors
        print(e)
        raise HTTPException(status_code=500, detail=f"Stripe Error: {e}")

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=f"Error: {e}")



@subscription_router.get("/api/subscriptions/get-subscription/{subscription_id}")
async def get_subscription(subscription_id: str):
    """
    Get Subscription Details
    """
    # Retrieve the subscription from Stripe
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # You can return the subscription details directly or map them to a schema
    return subscription


@subscription_router.get("/api/subscriptions/all-subscriptions")
def purchase_history(
        db: Session = Depends(get_db),
        token: str = Depends(oauth2_scheme)
):
    """
    Get user purchase history
    """

    current_user = get_user_from_token(token)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")

    subscriptions = db.query(schemas.Subscription).\
        join(schemas.User).join(schemas.Plan).\
        options(joinedload(schemas.Subscription.user)).\
        options(joinedload(schemas.Subscription.plan)).all()
    return subscriptions


# Cancelling subscription
@subscription_router.post("/api/subscriptions/{subscription_id}/cancel")
async def cancel_subscription(subscription_id: str, db: Session = Depends(get_db)):
    """
    Cancel a Subscription
    """
    try:
        stripe_subscription = stripe.Subscription.retrieve(subscription_id)
        stripe_subscription.modify(id=subscription_id, cancel_at_period_end=True)
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    subscription = db.query(schemas.Subscription).filter(
        schemas.Subscription.stripe_subscription_id == subscription_id).first()

    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found in db")

    # Update the subscription status
    subscription.status = 'cancel_at_eop'
    db.commit()

    return {"message": "Subscription will be cancelled at the end of the current billing period",
            "subscription": stripe_subscription}


@subscription_router.put("/subscriptions/{subscription_id}/change-plan")
async def change_subscription_plan(subscription_id: str, plan_id: str, db: Session = Depends(get_db)):
    """
    Modify subscription

    :param subscription_id: stripe suscription_id
    :param plan_id: plan id to access plan in database
    :param db: Session
    :return: updated_subscription object
    """
    # Retrieve the current subscription
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # Retrieve the plan details from the database
    plan = db.query(models.Plan).filter(models.Plan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")

    # Update the subscription with the new plan
    try:
        updated_subscription = stripe.Subscription.modify(
            subscription_id,
            items=[{'id': subscription['items']['data'][0].id, 'price': plan.stripe_price_id}]
        )
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Update the subscription status in the database
    try:
        updated_subscription_db = methods.update_subscription_status_in_db(db, subscription_id,
                                                                           updated_subscription.status, plan.id)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return {"message": "Subscription plan changed successfully", "subscription": updated_subscription_db}


@subscription_router.post("/api/subscriptions/{subscription_id}/resume")
def resume_subscription(subscription_id: str, db: Session = Depends(get_db)):
    """
    Resume a paused or canceled subscription
    """
    try:
        # Retrieve the subscription from Stripe
        stripe_subscription = stripe.Subscription.retrieve(subscription_id)
        stripe_subscription.modify(
            id=subscription_id,
            cancel_at_period_end=False
        )
        # Update the subscription status in the database
        db_subscription = db.query(schemas.Subscription).filter(
            schemas.Subscription.stripe_subscription_id == subscription_id).first()
        if db_subscription:
            db_subscription.status = 'active'
            db.commit()
        else:
            raise HTTPException(status_code=404, detail="Subscription not found in database")
    except stripe.error.StripeError as e:
        # Log the error for debugging
        print(f"Stripe error: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        # Log the error for debugging
        print(f"General error: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

    return {"message": "Subscription resumed successfully"}


@subscription_router.get("/api/subscriptions/purchase_history")
def purchase_history(
        db: Session = Depends(get_db),
        token: str = Depends(oauth2_scheme)
):
    """
    Get user purchase history
    """

    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    history = methods.order_history(user.id, db)
    return history
################################################## IS SERVICE ALLOWED #############################################################

@subscription_router.get("/api/subscriptions/is-service-allowed")
def service_permission(
        token: str = Depends(oauth2_scheme)
):
    """
    Get user permission
    """

    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    is_allowed = methods.is_service_allowed(user_id=user.id)
    return is_allowed
