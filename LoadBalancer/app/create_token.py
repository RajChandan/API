import jwt
from datetime import datetime, timedelta, timezone

SECRET_KEY = "dev-secret-change-me"
ALGORITHM = "HS256"

payload = {
    "sub": "user-123",
    "roles": ["customer", "premium"],
    "scopes" : ["orders:read","orders:write"],
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
}


token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
print(token)
