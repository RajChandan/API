from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
async def health():
    return {"status": "healthy", "server": "order_backend2"}


@app.api_route(
    "/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "DELETE"]
)
async def handle_all(path: str):
    return {
        "message": "Response from order backend 2",
        "path": path,
        "service": "order service",
    }
