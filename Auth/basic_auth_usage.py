from fastapi import FastAPI, Request, Depends
from basic_auth_api import (
    BasicAuthMiddleware,
    BasicAuth,
    InMemoryUserStore,
    hash_password,
)

app = FastAPI()

USERS = {"admin": hash_password("secret"), "user": hash_password("password")}
print(USERS, " === Users")


auth = BasicAuth(
    realm="My API", user_store=InMemoryUserStore(USERS), require_https=False
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/admin")
def secure(request: Request):
    user = request.state.user
    print(user, " === Authenticated User")
    return {"message": f"Hello, {user['username']}!"}


app.add_middleware(
    BasicAuthMiddleware,
    authenticator=auth,
    protected_prefix="/admin",
    exempt_path={"/health", "/docs", "/redoc"},
)
