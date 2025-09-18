from fastapi import FastAPI,Request,Response,HTTPException

app = FastAPI(title="Cookies")

SESSION_COOKIE = "sessionid"
user_by_session = {}

@app.post("/login")
def login(response:Response,username:str = "user"):
    sid = f"sid_{username}"
    user_by_session[sid] = username
    response.set_cookie(key=SESSION_COOKIE,value=sid,max_age=3600,httponly=True,secure=False,samesite="lax",path="/")
    return {"status":"ok","message":"Logged In"}


@app.get("/me")
def me(request:Request):
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid or sid not in user_by_session:
        raise HTTPException(status_code=401,detail="Not Authenticated")
    return {"username":user_by_session[sid]}


@app.post("/logout")
def logout(response:Response,request:Request):
    sid = request.cookies.get(SESSION_COOKIE)
    if sid and sid in user_by_session:
        del user_by_session[sid]
    response.delete_cookie(SESSION_COOKIE,path="/")
    return {"status":"ok","message":"Logged Out"}