from fastapi import FastAPI, Depends
from basic_auth import BasicAuthMiddleware, BasicAuth, InMemoryUserStore, hash_password

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
def secure(user=Depends(auth)):
    return {"message": f"Hello, {user.username}!"}


app.add_middleware(
    BasicAuthMiddleware,
    authenticator=auth,
    protected_prefix="/admin",
    exempt_path=["/health", "/docs", "/redoc"],
)
