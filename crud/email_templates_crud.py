from fastapi import HTTPException, Depends, status
import models
import schemas
from sqlalchemy.orm import Session



def create_email_template(template: models.EmailTemplateCreate,user_id: int, db: Session):
    db_email_template = schemas.EmailTemplate(
        user_id=user_id,
        name=template.name,
        subject=template.subject,
        body=template.body,

    )
    db.add(db_email_template)
    db.commit()
    db.refresh(db_email_template)

    return db_email_template


def get_user_templates(db: Session, user_id: int):
    email_templates = db.query(schemas.EmailTemplate).filter(
        schemas.EmailTemplate.user_id == user_id).all()
    return email_templates


def get_user_templates_by_id(template_id:int, db: Session):
    email_template = db.query(schemas.EmailTemplate).filter(
        schemas.EmailTemplate.id == template_id).first()
    return email_template


def update_email_template(template_id: int, template: models.EmailTemplateCreate, db: Session):
    db_template = db.query(schemas.EmailTemplate).filter(schemas.EmailTemplate.id == template_id).first()
    if db_template is None:
        raise HTTPException(status_code=404, detail="Template not found")
    else:
        db_template.name = template.name
        db_template.subject = template.subject
        db_template.body = template.body

        db.commit()
        db.refresh(db_template)

    return db_template


def delete_email_template(template_id: int, db: Session):
    db_template = db.query(schemas.EmailTemplate).filter(schemas.EmailTemplate.id == template_id).first()
    if db_template is None:
        raise HTTPException(status_code=404, detail="Template not found")
    print('i am here')
    db.delete(db_template)
    db.commit()
    return


