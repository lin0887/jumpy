import os
from typing import Union
from fastapi import FastAPI, UploadFile
import time
from datetime import timedelta
from fastapi import Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from jumpy import counter
from threading import Thread
import uvicorn

# openssl rand -hex 32
SECRET_KEY = "5548a81bf036952bf5e88b0e8f9e9617f6e019bba806484cfa77a911bdee4206"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SALT = "10dd0cd14462a4dda5a6a3ec4b71f2e0"

app = FastAPI()
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Contestant(BaseModel):
    id: str
    name: str
    school: str
    score: int
    grade: str
    group: str
    contest: str

class Register(BaseModel):
    name: str
    school: str
    grade: str
    group: str
    contest: str

class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


def unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})

def _read_user(username) -> User:
    if username == "admin":
        return User(username=username, password=pwd_context.hash("admin" + SALT))
    return User.get_by_username(username)

def auth(username: str, password: str) -> User:
    user = _read_user(username)
    if not user:
        return None
    if not pwd_context.verify(password + SALT, user.password):
        return None
    return user

async def dep_user(token: str = Depends(oauth2_bearer)):
    error = unauthorized("Could not validate access token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise error
        # 验证 token 是否过期
        expires = payload.get("exp")
        if expires < time.time():
            raise unauthorized("Token has expired")
    except JWTError:
        raise error
    user = _read_user(username)
    if user is None:
        raise error
    return user

def _create_token(data: dict, expires: timedelta = timedelta(minutes=60)) -> str:
    data = {**data, "exp": time.time() + expires.seconds}
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return token

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/token", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = auth(form.username, form.password)
    if not user:
        raise unauthorized("Incorrect username or password")
    token = _create_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check")
async def read_users_me(current_user: User = Depends(dep_user)):
    if current_user:
        return status.HTTP_200_OK
    else:
        return status.HTTP_401_UNAUTHORIZED

@app.post("/uploadCSV")
async def uploadCSV(current_user: User = Depends(dep_user),file: Union[UploadFile, None] = None):
    if current_user:
        if not file:
                return {"message": "No upload file sent"}
        else:
            if file.content_type != "text/csv":
                print(file.content_type)
                return {"message": "File is not CSV"}
            else:
                data = pd.read_csv(file.file)
                if os.path.exists("contestants.json"):
                    df = pd.read_json("contestants.json")
                    data = df.append(data, ignore_index=True)
                with open("contestants.json", "w") as f:
                    f.write(data.to_json(orient="records"))
                return status.HTTP_200_OK
    return status.HTTP_401_UNAUTHORIZED
    
@app.post("/uploadVideo/{id}")
async def uploadFile(current_user: User = Depends(dep_user),id: str = None,file: UploadFile = None):
    if current_user:
        if not file:
            return {"message": "No upload file sent"}
        else:
            print(file.content_type)
            filename = id + '.' + file.filename.split(".")[-1]
            with open(filename, "wb") as buffer:
                buffer.write(file.file.read())
            #Thread(target = counter.jumpCounting , args =(filename,)).start()
            
            return status.HTTP_200_OK
    else:
        return status.HTTP_401_UNAUTHORIZED

@app.get("/contestants")
async def rankBoard(current_user: User = Depends(dep_user)):#
    if current_user:
        data = open("contestants.json", "r")
        return Response(content=data.read(), media_type="application/json")
    else:
        return status.HTTP_401_UNAUTHORIZED

@app.post("/contestants")
async def contestants(current_user: User = Depends(dep_user),register: Register = None):  # type: ignore
    if current_user:
        data = pd.read_json("contestants.json")
        last_id = data["id"].iloc[-1]
        new_id = last_id[:-1] + str(int(last_id[-1]) + 1)
        print(new_id)
        contestant = Contestant(id=new_id,name=register.name, school=register.school, score=0, grade=register.grade, group=register.group, contest=register.contest)
        data = data.append(contestant.dict(), ignore_index=True)
        with open("contestants.json", "w") as f:
            f.write(data.to_json(orient="records"))
        return status.HTTP_200_OK
    else:
        return status.HTTP_401_UNAUTHORIZED

@app.get("/contestants/{contestant_id}")
async def getContestant(current_user: User = Depends(dep_user),contestant_id: str = None):
    if current_user:
        data = pd.read_json("./contestants.json")
        contestant = data[data["id"] == contestant_id]

        return Response(content=contestant.to_json(orient="records"), media_type="application/json")
    else:
        return status.HTTP_401_UNAUTHORIZED

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)