from fastapi import FastAPI, Depends
from jwt_auth_plugin import JWTAuth, JWTAuthSettings
from app.auth import router as auth_router

app = FastAPI(title="JWT Authentication")

app.include_router(auth_router)
auth = JWTAuth(JWTAuthSettings.from_env())


@app.get("/public")
def public():
    return {"ok": True, "message": "This is a public endpoint"}


@app.get("/me")
def me(user=Depends(auth.current_user)):
    return {"sub": user["sub"], "roles": user["_roles"], "scopes": user["_scopes"]}


@app.get("/admin")
def admin(user=Depends(auth.require_roles(["admin"]))):
    return {"ok": True, "message": "Welcome, admin!", "user": user["sub"]}
