import time
from fastapi import Request
from fastapi.responses import JSONResponse


def get_client_identity(request:Request) -> str:
    auth_user = getattr(request.state,"user_id",None)

    if auth_user:
        return f"user:{auth_user}"

    client_host = request.client.host if request.client else "unknown"

    return f"ip:{client_host}"



async def enforce_rate_limit(request:Request,service_state):
    policy = service_state.policy

    if not policy.rate_limit_enabled:
        return None

    redis_client = request.app.state.redis_client
    identity = get_client_identity(request)

    window = int(time.time() // policy.rate_limit_window_seconds)

    key = f"rl:{service_state.name}:{identity}:{window}"

    current = await redis_client.incr(key)

    if current == 1:
        await redis_client.expire(key,policy.rate_limit_window_seconds)

    if current > policy.rate_limit_requests:
        retry_after = policy.rate_limit_window_seconds

        return JSONResponse(status_code=429,
        content={"error":"rate limit exceeded","service":service_state.name,
        "limit":policy.rate_limit_requests,"window_seconds":policy.rate_limit_window_seconds},
        headers= {"Retry-After":str(retry_after),"X-RateLimit-Limit":str(policy.rate_limit_requests),"X-RateLimit-Remaining":"0"})

    
    remaining = max(0,policy.rate_limit_requests - current)
    request.state.rate_limit_headers = {"X-RateLimit-Limit":str(policy.rate_limit_requests),"X-RateLimit-Remaining":str(remaining)}

    return None

    