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
        print("Key:", key)
        now = _now()
        window_start = now - self.window
        print("Now:", now, "Window Start:", window_start)
        pipe = self.r.pipeline()
        pipe.zremrangebyscore(key,0,window_start)
        pipe.zcard(key)
        res = await pipe.execute()
        print("Pipeline Result:", res[0])
        count = int(res[1])
        print("Count:", count)

        if count < self.limit:
            await self.r.zadd(key,{str(now):now})
            await self.r.expire(key,self.window)
            remaining = self.limit - (count + 1)
            print("Allowed:", count + 1, "Remaining:", remaining)
            earliest = await self.r.zrange(key,0,0,withscores=True)
            print("Earliest:", earliest)
            reset_in = 0.0 if not earliest else max(0.0,self.window - (now - earliest[0][1]))
            print("Reset In:", reset_in)
            return Decision(allowed=True,remaining=remaining,reset_in=reset_in)
        else:
            earliest = await self.r.zrange(key,0,0,withscores=True)
            print("Earliest:", earliest)
            reset_in = 0.0 if not earliest else max(0.0,self.window - (now - earliest[0][1]))
            print("Denied:", count, "Reset In:", reset_in)
            return Decision(allowed=False,remaining=0,reset_in=reset_in)
        

class SlidingCounterLimiter:
    def __init__(self,r:redis.Redis,limit:int,window_seconds:int,prefix:str="rl:sc"):
        self.r = r
        self.limit = limit
        self.window = window_seconds
        self.prefix = prefix


    def _keys(self,identifier:str) -> tuple[str,str]:
        now_win = int(_now() // self.window)
        prev_key = f"{self.prefix}:{identifier}:{now_win - 1}"
        curr_key = f"{self.prefix}:{identifier}:{now_win}"
        return prev_key,curr_key
    
    async def allow(self,identifier:str) -> Decision:
        prev_key,curr_key = self._keys(identifier)
        print(f"Prev Key: {prev_key}, Curr Key: {curr_key}")
        now = _now()
        elapsed = now % self.window
        print("Now:", now, "Elapsed:", elapsed)
        weight_prev = (self.window - elapsed) // self.window
        print("Weight Prev:", weight_prev)
        pipe = self.r.pipeline()
        pipe.get(prev_key)
        pipe.get(curr_key)
        prev_count_s,curr_count_s = await pipe.execute()
        prev_cnt = int(prev_count_s) if prev_count_s else 0
        curr_cnt = int(curr_count_s) if curr_count_s else 0
        print("Prev Count:", prev_cnt, "Curr Count:", curr_cnt)

        approx = prev_cnt * weight_prev + curr_cnt
        print("Approximate Count:", approx)

        if approx < self.limit:
            pipe = self.r.pipeline()
            pipe.incr(curr_key,1)
            pipe.expire(curr_key,self.window * 2)
            await pipe.execute()

            curr_cnt = curr_cnt + 1
            approx = prev_cnt * weight_prev + curr_cnt
            remaining = self.limit - approx
            print("Allowed:", approx, "Remaining:", remaining)
            reset_in = self.window - elapsed
            print("Reset In:", reset_in)
            return Decision(allowed=True,remaining=int(remaining),reset_in=reset_in)
        else:
            reset_in = self.window - elapsed
            print("Denied:", approx, "Reset In:", reset_in)
            return Decision(allowed=False,remaining=0,reset_in=reset_in)



class TokenBucketLimiter:
    def __init__(self,r:redis.Redis,capacity:int,refill_rate:float,prefix:str="rl:tb"):
        self.r = r
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.prefix = prefix

    
    def _key(self,identifier:str) -> str:
        return f"{self.prefix}:{identifier}"
    
    async def allow(self,identifier:str) -> Decision:
        key = self._key(identifier)
        print(f"Key: {key}")
        now = _now()
        data = await self.r.hgetall(key)
        print(f"Data: {data}")

        if not data:
            tokens = self.capacity - 1
            await self.r.hset(key,mapping={"tokens":tokens,"ts":now})
            await self.r.expire(key,int(max(2*self.capacity / max(self.refill_rate,0.001),60)))
            print("Allowed: 1, Remaining:", tokens)
            return Decision(allowed=True,remaining=int(tokens),reset_in=1.0/max(self.refill_rate,0.001))

        


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
            "sliding_log": "/sliding-log?limit=10&window=60",
            "sliding_counter": "/sliding-counter?limit=10&window=60",
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


@app.get("/sliding_log",tags=["sliding"])
async def sliding_log(request:Request,limit:int=Query(10,ge=1,le=100),window:int=Query(60,ge=1,le=3600)):
    r = await get_redis()
    limiter = SlidingLogLimiter(r,limit,window)
    identifier = client_identifier(request)
    decision = await limiter.allow(identifier)
    return finalize_or_429(request,decision,limit,{"Strategy":"Sliding Log","limit":limit,"window":window})


@app.get("/sliding_counter",tags=["sliding"])
async def sliding_counter(request:Request,limit:int=Query(10,ge=1),window:int=Query(60,ge=1)):
    r = await get_redis()
    limiter = SlidingCounterLimiter(r,limit,window)
    identifier = client_identifier(request)
    decision = await limiter.allow(identifier)
    return finalize_or_429(request,decision,limit,{"Strategy":"Sliding Counter","limit":limit,"window":window})