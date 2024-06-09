from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session
from schemas import SessionLocal
import schemas

def block_expired_demo_plans():
    db: Session = SessionLocal()
    try:
        # Get the current time
        current_time = datetime.utcnow()

        # Query for active demo plans
        demo_plans = db.query(schemas.Subscription).join(schemas.Plan).filter(
            schemas.Plan.plan_type_name == 'Starter',  # Assuming 'Starter' is the demo plan name
            schemas.Subscription.status == 'active'
        ).all()

        for plan in demo_plans:
            # Calculate the demo end date based on creation_date and time_period
            if plan.plan.time_period:
                end_date = plan.created_at + timedelta(days= 30*plan.plan.time_period)
            else:
                end_date = plan.created_at + timedelta(days=30)  # Default demo period if not specified

            # If the current time is past the end date, mark the plan as inactive
            if current_time >= end_date:
                plan.status = 'inactive'
                db.commit()

    except Exception as e:
        print(f"Error blocking expired demo plans: {e}")
    finally:
        db.close()

# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(block_expired_demo_plans, 'interval', hours=12)  # Run every 12 hours
scheduler.start()