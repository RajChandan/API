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
    return request.headers.get("X-API-Key") or request.client.host


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



# --------------------
# LIMITER STRATEGIES
# --------------------


class FixedWindowLimiter:
    ''' 
    Simple Counter per fixed window 
    '''

    def __init__(self,r:redis.Redis,limit:int,window_seconds:int,prefix:str="rl:fw"):
        self.r = r
        self.limit = limit
        self.window = window_seconds
        self.prefix = prefix

    def _key(self,identifier:str) -> str:
        current_window = int(_now() // self.window)
        return f"{self.prefix}:{identifier}:{current_window}"
    
    async def allow(self,identifier:str) -> Decision:
        key = self._key(identifier)
        print("Key:", key)
        current = await self.r.incr(key)
        print("Current:", current)
        if current == 1:
            await self.r.expire(key,self.window)
            ttl = self.window
            print("TTL:", ttl, "set ttl")
        else:
            ttl = await self.r.ttl(key)
            if ttl < 0:
                await self.r.expire(key,self.window)
                ttl = self.window
                print("TTL:", ttl, "reset ttl")
            
        if current <= self.limit:
            print("Allowed:", current)
            return Decision(allowed=True,remaining=self.limit - current,reset_in=float(ttl))
        else:
            print("Denied:", current)
            return Decision(allowed=False,remaining=0,reset_in=float(ttl))



class SlidingLogLimiter:

    def __init__(self,r:redis.Redis,limit:int,window_seconds:int,prefix:str="rl:sl"):
        self.r = r
        self.limit = limit
        self.window = window_seconds
        self.prefix = prefix

    
    def _key(self,identifier:str) -> str:
        return f"{self.prefix}:{identifier}"
    
    async def allow(self,identifier:str) -> Decision:
        key = self._key(identifier)
        now = _now()
        window_start = now - self.window
        
        pipe = self.r.pipeline()
        pipe.zremrangebyscore(key,0,window_start)
        pipe.zcard(key)
        res = await pipe.execute()
        count = int(res[1])

        if count < self.limit:
            await self.r.zadd(key,{str(now):now})
            await self.r.expire(key,self.window)
            remaining = self.limit - (count + 1)
            earliest = await self.r.zrange(key,0,0,withscores=True)
            reset_in = 0.0 if not earliest else max(0.0,self.window - (now - earliest[0][1]))
            return Decision(True,remaining,reset_in)
        else:
            earliest = await self.r.zrange(key,0,0,withscores=True)
            reset_in = 0.0 if not earliest else max(0.0,self.window - (now - earliest[0][1]))
            return Decision(False,0,reset_in)



# --------------------
# Fast API
# --------------------

app = FastAPI(title="Rate Limiter API",version="1.0.0")

@app.middleware("http")
async def add_rate_headers(request:Request,call_next):
    print("In middleware")
    response : Response = await call_next(request)
    hdrs = getattr(request.state,"rate_limit_headers",None)
    if hdrs:
        for k,v in hdrs.items():
            response.headers[k] = v
    print(response.headers)
    return response


@app.get("/",tags=["meta"])
def meta():
    return {
        "name": "Rate Limiting Lab",
        "how": "Use X-API-Key to simulate different users; otherwise IP is used.",
        "endpoints": {
            "whoami": "/whoami",
            "fixed": "/fixed?limit=10&window=60",
            # "sliding_log": "/sliding-log?limit=10&window=60",
            # "sliding_counter": "/sliding-counter?limit=10&window=60",
            # "token_bucket": "/token-bucket?capacity=10&refill_rate=2.0",
            # "leaky_bucket": "/leaky-bucket?capacity=10&leak_rate=2.0",
        }
    }



@app.get("/whoami",tags=["meta"])
def whoami(request:Request):
    return {
        "client_ip": request.client.host,
        "client_port": request.client.port,
        "api_key": request.headers.get("X-API-Key")
    }


# FIXED WINDOW

@app.get("/fixed",tags=["Fixed"])
async def fixed(request:Request,limit:int=Query(10,ge=1,le=100),window:int=Query(60,ge=1,le=3600)):
    r = await get_redis()
    limiter = FixedWindowLimiter(r,limit,window)
    identifier = client_identifier(request)
    decision = await limiter.allow(identifier)
    return finalize_or_429(request,decision,limit,{"Strategy":"Fixed Window","limit":limit,"window":window})
