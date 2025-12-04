## Introduction 📖

This project is a FastAPI-based application that implements authentication and rate-limiting strategies. It provides secure access to endpoints using Basic Authentication and ensures fair usage of resources through various rate-limiting techniques.

## Features ✨

- **Basic Authentication** 🔒: Secure endpoints using HTTP Basic Authentication.
- **Rate Limiting** ⏳: Implemented multiple strategies to control API usage:
  - Fixed Window 🪟
  - Sliding Log 📜
  - Sliding Counter 🔢
  - Token Bucket 🪣
  - Leaky Bucket 💧
- **Middleware** 🛡️: Custom middleware for authentication and rate limiting.
- **Dependency Injection** 🧩: Utilizes FastAPI's `Depends` for injecting dependencies.

## Endpoints 🌐

### Authentication 🔑

- **`/admin`**: Protected endpoint that requires Basic Authentication.

### Rate Limiting ⚙️

- All endpoints are rate-limited using one of the implemented strategies.

## Authentication 🔐

### Basic Authentication

Basic Authentication is implemented using `BasicAuthMiddleware` and `BasicAuth` classes. The middleware validates credentials and sets the authenticated user in the request state.

#### Example Usage 🛠️

```python
from fastapi import FastAPI, Depends
from Auth.basic_auth_api import BasicAuth

app = FastAPI()

@app.get("/admin")
async def admin_route(user: str = Depends(BasicAuth())):
    return {"message": f"Welcome, {user}"}
```

## Rate Limiting Strategies 📊

### Fixed Window 🪟

Limits the number of requests within a fixed time window.

### Sliding Log 📜

Tracks request timestamps and allows requests based on a sliding time window.

### Sliding Counter 🔢

Maintains a counter that resets periodically, allowing requests within the sliding window.

### Token Bucket 🪣

Tokens are added to a bucket at a fixed rate, and requests consume tokens.

### Leaky Bucket 💧

Requests are processed at a fixed rate, and excess requests are queued or dropped.

## Installation 🛠️

Each file in this project is an independent FastAPI project. Follow the steps below to run any specific project:

1. Clone the repository:
   ```bash
   git clone https://github.com/RajChandan/API.git
   ```
2. Navigate to the project directory:
   ```bash
   cd API
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the desired FastAPI project:

   ```bash
   uvicorn <filename>:app --reload
   ```

   Replace `<filename>` with the name of the file you want to run (e.g., `main`, `cookie`, `pagination`, etc.).

5. Access the API documentation at `http://127.0.0.1:8000/docs`.

## Contributing 🤝

Contributions are welcome! Please fork the repository and create a pull request with your changes.
