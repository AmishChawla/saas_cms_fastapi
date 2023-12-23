from typing import Union
from pydantic import BaseModel

class TokenData(BaseModel):
    username: Union[str, None] = None
    role: Union[str, None] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"



class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str