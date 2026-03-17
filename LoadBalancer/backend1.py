fro fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/health")
async def health():
    return {"status":"healthy","server":"backend1"}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def handle_all(path:str):
    return {"status":"ok","message":"Response from backend1","path":path}
