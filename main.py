from datetime import datetime,timedelta,timezone
from typing import Optional
from uuid import uuid4

import jwt
from fastapi import Depends,FastAPI,HTTPException,Request,Response,status
from fastapi.security import HTTPBasic,HTTPBasicCredentials,HTTPAuthorizationCredentials,HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel


app = FastAPI(title="Authentication")

pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

USER_DB = {
    "chandan": {"username": "chandan", "password_hash":pwd_context.hash("secret123"),"roles":["user"]}
}

# ====== Settings / secrets ======
JWT_SECRET = "CHANGE_ME_in_env"
JWT_ALG = "HS256"
ACCESS_TTL_MIN = 15
REFRESH_TTL_DAYS = 7
SESSION_COOKIE = "sessionid"
SESSION_STORE = {}


class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token:str
    token_type:str="bearer"
    expires_in:int

class ProfileOut(BaseModel):
    username:str
    roles:list[str]


def verify_password(plain:str,hashed:str) -> bool:
    return pwd_context.verify(plain,hashed)


def create_jwt(username:str,ttl_minutes:int=ACCESS_TTL_MIN) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":username,
        "iat":int(now.timestamp()),
        "exp":int((now + timedelta(minutes=ttl_minutes)).timestamp()),
        "jti":str(uuid4())
    }

    return jwt.encode(payload,JWT_SECRET,algorithm=JWT_ALG)

def decode_jwt(token:str) -> Optional[dict]:
    try:
        return jwt.decode(token,JWT_SECRET,algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401,detail="Invalid token")
    

# ========== Basic Auth ==========

basic = HTTPBasic()

def basic_guard(creds:HTTPBasicCredentials = Depends(basic)) -> str:
    user = USER_DB.get(creds.username)

    if not user or not verify_password(creds.password,user["password_hash"]):
        raise HTTPException(status_code=401,details="Invalid credentials",headers={"WWW-Authenticate":"Basic realm='Restricted'"})
    return creds.username


@app.get("/admin/basic-protected",response_model=ProfileOut,tags=["basic"])
def admin_basic(user:str=Depends(basic_guard)):
    u = USER_DB[user]
    return ProfileOut(username=u["username"],roles=u["roles"])


# ========== Bearer Auth ==========

bearer = HTTPBearer(auto_error=False)

def bearer_guard(creds:Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> str:
    if creds is None or creds.scheme.lower()!= "bearer":
        raise HTTPException(status_code=401,detail="Invalid or missing authentication",headers={"WWW-Authenticate":"Bearer"})
    payload = decode_jwt(creds.credentials)

    return payload["sub"]


@app.post("/auth/login-jwt",response_model=TokenOut,tags=["jwt"])
def login_jwt(body:LoginIn):
    user = USER_DB.get(body.username)
    if not user or not verify_password(body.password,user["password_hash"]):
        raise HTTPException(status_code=401,detail="Invalid credentials")
    token = create_jwt(user["username"],ttl_minutes=ACCESS_TTL_MIN)
    return TokenOut(access_token=token,expires_in=ACCESS_TTL_MIN*60)

@app.get("/me/jwt",response_model=ProfileOut,tags=["jwt"])
def me_jwt(username:str=Depends(bearer_guard)):
    u = USER_DB[username]
    return ProfileOut(username=u["username"],roles=u["roles"])


# ========== Session Auth ==========

@app.post("/auth/login-cookie",tags=["cookie"])
def login_cookie(body:LoginIn,response:Response):
    user = USER_DB.get(body.username)
    if not user or not verify_password(body.password,user["password_hash"]):
        raise HTTPException(status_code=401,detail="Invalid credentials")
    sid =str(uuid4())
    SESSION_STORE[sid] = body.username
    response.set_cookie(key = SESSION_COOKIE,value = sid,httponly = True, samesite="lax",max_age=60 * 60,path = "/")
    return {"status":"ok","message":"Session Created"}

def session_guard(request:Request) -> str:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid or sid not in SESSION_STORE:
        raise HTTPException(status_code=401,detail="Missing or invalid cookie")
    return SESSION_STORE[sid]


@app.get("/me/session",response_model=ProfileOut,tags=["cookie"])
def me_seesion(user:str=Depends(session_guard)):
    u = USER_DB[user]
    return ProfileOut(username=u["username"],roles=u["roles"])


@app.post("/auth/logout-cookie",tags=["cookie"])
def logout_cookie(response:Response,username : str = Depends(session_guard)):
    sid_to_delete = None
    for sid, user in list(SESSION_STORE.items()):
        if user == username:
            sid_to_delete = sid
            break
    if sid_to_delete:
        del SESSION_STORE[sid_to_delete]
    response.delete_cookie(SESSION_COOKIE,path="/")
    return {"Status":"ok","message":"Logged Out"}


 
  


