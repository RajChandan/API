from __future__ import annotations
import os
import time
import math
from typing import Optional,Dict,Any
from dotenv import load_dotenv
from fastapi import FastAPI,Request,Response,Query,HTTPException
from pydantic import BaseModel
import redis.asyncio as redis

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")
print("REDIS_URL:", REDIS_URL)

_redis: Optional[redis.Redis] = None

async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _redis              


def _now() -> float:
    return time.time()

def client_identifier(request:Request) -> str:
    return request.header.get("X-API-Key") or request.client.host


class Decision(BaseModel):
    allowed: bool
    remaining: int
    reset_in: float


    def to_headers(self,limit_or_capacity:int) -> Dict[str,str]:
        return {
            "X-RateLimit-Limit":str(limit_or_capacity),
            "X-RateLimit-Remaining": str(max(self.remaining,0)),
            "X-RateLimit-Reset":str(int(_now() + max(self.reset_in,0)))
        }
    

def finalize_or_429(request:Request,decision:Decision,limit_or_capacity:int,payload:Dict[str,Any]) -> Dict[str,Any]:
    headers = decision.to_headers(limit_or_capacity)
    if not decision.allowed:
        headers["Retry-After"] = str(max(1,math.ceil(decision.reset_in or 1)))
        raise HTTPException(status_code=429,detail="Too Many Requests",headers=headers)
    
    request.state.rate_limit_headers = headers
    return payload
