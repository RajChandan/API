from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
async def health():
    return {"status": "Healthy", "server": "backend3"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def handle_all(path: str):
    return {"status": "ok", "message": "Response from backend3", "path": path}
