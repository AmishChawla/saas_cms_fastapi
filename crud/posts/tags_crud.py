from sqlalchemy.orm import Session
import schemas, models
from fastapi import APIRouter, FastAPI, HTTPException, Depends, status, File, UploadFile, Request, Path, Body, Query, \
    Form

def get_tag(db: Session, tag_id: int):
    return db.query(schemas.Tag).filter(schemas.Tag.id == tag_id).first()

def get_tags(db: Session, skip: int = 0, limit: int = 100):
    return db.query(schemas.Tag).offset(skip).limit(limit).all()


def create_tag(db: Session, tag_create: models.TagCreate, user_id: int):
    # Normalize the tag by converting to lowercase and removing whitespace
    normalized_tag = tag_create.tag.strip().lower()

    # Check if the tag already exists
    existing_tag = db.query(schemas.Tag).filter(schemas.Tag.tag == normalized_tag).first()

    if existing_tag:
        # Check if the association already exists
        existing_association = db.query(schemas.TagUser).filter(
            schemas.TagUser.user_id == user_id,
            schemas.TagUser.tag_id == existing_tag.id
        ).first()

        if not existing_association:
            # Association does not exist, create it
            tag_user = schemas.TagUser(user_id=user_id, tag_id=existing_tag.id)
            db.add(tag_user)
            db.commit()
            db.refresh(tag_user)
            return existing_tag
        elif existing_association:
            return existing_tag
    else:
        # Tag does not exist, create it
        new_tag = schemas.Tag(tag=normalized_tag)
        db.add(new_tag)
        db.commit()
        db.refresh(new_tag)

        # Create the association in tag_user
        tag_user = schemas.TagUser(user_id=user_id, tag_id=new_tag.id)
        db.add(tag_user)
        db.commit()
        db.refresh(tag_user)

        return new_tag



def update_tag(db: Session, user_id: int, old_tag_id: int, new_tag_details: models.TagUpdate):
    # Create a new tag with the updated details
    delete_tag_user_association(db=db,tag_id=old_tag_id, user_id=user_id)
    new_tag = create_tag(db, new_tag_details, user_id=user_id)
    # Return the new tag details
    return new_tag


def update_tag_user_associations(db: Session, old_tag_id: int, new_tag_id: int, user_id: int):
    """
    Updates the tag_user associations to replace the old tag with the new tag for a specific user.

    :param db: SQLAlchemy session
    :param old_tag_id: ID of the tag being replaced
    :param new_tag_id: ID of the new tag
    :param user_id: ID of the user whose tag associations are being updated
    """
    # Query the tag_user table to find entries associated with the old tag and the user
    query = db.query(schemas.TagUser).filter(
        schemas.TagUser.tag_id == old_tag_id,
        schemas.TagUser.user_id == user_id
    )

    # Update the queried entries to use the new tag_id
    query.update({
        'tag_id': new_tag_id
    }, synchronize_session=False)

    # Commit the changes
    db.commit()


def delete_tag_user_association(db: Session, tag_id: int, user_id: int):
    """
    Deletes the association between a tag and a user by removing the relevant record from the TagUser table.

    :param db: SQLAlchemy session
    :param tag_id: ID of the tag whose association with the user is to be deleted
    :param user_id: ID of the user whose association with the tag is to be deleted
    """
    # Query the TagUser table to find the entry associated with the tag and the user
    query = db.query(schemas.TagUser).filter(
        schemas.TagUser.tag_id == tag_id,
        schemas.TagUser.user_id == user_id
    )

    # Delete the queried entry
    query.delete(synchronize_session=False)

    # Commit the changes
    db.commit()
    return