from sqlmodel import (Field,SQLModel,create_engine,String)
from uuid import uuid4

DBengine = create_engine("sqlite:///database.db")

class Users(SQLModel, table=True):
    id: str = Field(default=str(uuid4()),primary_key=True)
    username: str = Field(String,unique=True)
    email: str = Field(String,unique=True)
    password: str = Field(String)

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    username: str

class UserInDB(TokenData):
    email: str
    password: str
    

SQLModel.metadata.create_all(DBengine)

