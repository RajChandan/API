from fastapi import FastAPI, Depends
from jwt_auth_plugin import JWTAuth, JWTAuthSettings

app = FastAPI(title="JWT Authentication")
auth = JWTAuth(JWTAuthSettings.from_env())


@app.get("/public")
def public():
    return {"ok": True, "message": "This is a public endpoint"}


@app.get("/me")
def me(user=Depends(auth.current_user)):
    return {"sub": user["sub"], "roles": user["_roles"], "scopes": user["_scopes"]}
