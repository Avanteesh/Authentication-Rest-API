from fastapi import Depends,FastAPI,HTTPException,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError,jwt
from sqlmodel import (Session, select)
from models import (Users,DBengine,Token,TokenData,UserInDB)
from passlib.context import CryptContext

SECRET_KEY = "b9925d631e7e6873c533323deb1328d938b7381f91c50490ef245bac963b7400"
ACCESS_TOKEN_EXPIRE_TIME=30
ALGORITHM="HS256"
app = FastAPI()
session = Session(DBengine)
pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_text: str, hashed: str):
    return pwd_context.verify(plain_text, hashed)

def getUser(username: str):
    sql_query = select(Users).where(Users.username == username)
    query_response = session.exec(sql_query).first()
    if query_response:
        return UserInDB(
          email=query_response.email,password=query_response.password,
          username=query_response.username
        )

def authenticate(username: str, password: str):
    user = getUser(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_access_token(data: dict, expiretime: timedelta or None = None):
    toEncoded = data.copy()
    if expiretime:
        expire = datetime.utcnow() + expiretime
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    toEncoded.update({"exp": expire})
    encoded_jwt = jwt.encode(toEncoded, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt    

async def get_current_user(token: str=Depends(oauth_2_scheme)):
    credential_exception = HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Could not validate credentials",
      headers={"WWW-Authenticate":"Bearer"}
    )
    try:       
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data =  TokenData(username=username)
    except JWTError:
        raise credential_exception
    user = getUser(username=token_data.username)
    if user is None:
        raise credential_exception
    return user

async def get_current_active_user(current_user: UserInDB=Depends(get_current_user)) -> Users:
    user_data = session.exec(select(Users).where(
      Users.email == current_user.email
    ).where(
      Users.username == current_user.username
      ).where(Users.password == current_user.password)
    ).first()
    return user_data

@app.post("/sign-up")
async def signIn(user: Users):
    query = select(Users).where(Users.id == user.id).where(Users.email == user.email).where(Users.username == user.username)
    result = session.exec(query).fetchall()
    if len(result) != 0:
        return {"message":"Oops something is wrong!"}
    else:
        session.add(Users(
          id=user.id,username=user.username,
          email=user.email,password=get_hash(user.password)
        ))
        session.commit()
        return {"message":"data saved!!"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm=Depends()):
    user = authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
         status_code=status.HTTP_401_UNAUTHORIZED,
         detail="Incorrect username or password",
         headers={"WWW-Authenticate":"Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_TIME)
    access_token = create_access_token(
     data={"sub":form_data.username},expiretime=access_token_expires
    )
    return {"access_token":access_token,"token_type":"bearer"}

@app.get("/users/you/", response_model=Users)
async def read_own(current_user: Users=Depends(get_current_active_user)):
    return current_user
