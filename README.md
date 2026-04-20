## Introduction 📖

This project is a comprehensive FastAPI-based collection of applications including a **Load Balancer**, **Authentication Systems**, and **Rate-Limiting Strategies**. It provides secure access to endpoints, distributes traffic across multiple backends, and ensures fair usage of resources.

## Features ✨

### Load Balancer 🔀

- **Multi-Backend Load Balancing**: Distribute traffic across multiple backend servers
- **Health Checking** 🏥: Active health checks with configurable thresholds
- **Passive Failure Detection** 🔍: Detect backend failures during normal operation
- **Prometheus Metrics** 📊: Comprehensive monitoring with request counts, durations, and backend health
- **Request Retry Logic** 🔄: Automatic retry on failures with configurable policies
- **Distributed Request Logging** 📝: Track requests with unique IDs across the system
- **Rate Limiting** 🚦: Control concurrent requests and request rates

### Authentication & Rate Limiting 🔐

- **Basic Authentication** 🔒: Secure endpoints using HTTP Basic Authentication
- **JWT Authentication** 🎫: JSON Web Token-based authentication with JWKS support
- **Rate Limiting Strategies** ⏳: Multiple implementations to control API usage:
  - Fixed Window 🪟
  - Sliding Log 📜
  - Sliding Counter 🔢
  - Token Bucket 🪣
  - Leaky Bucket 💧
- **Middleware** 🛡️: Custom middleware for authentication and rate limiting
- **Dependency Injection** 🧩: Utilizes FastAPI's `Depends` for injecting dependencies

## Project Structure 📁

```
Rest/
├── LoadBalancer/          # HTTP Load Balancer with health checking
├── Auth/                  # Authentication implementations
├── main.py               # Various standalone examples
├── cookie.py             # Cookie handling
├── jwt_main.py           # JWT authentication
├── pagination.py         # Pagination implementation
├── rate_limiter.py       # Rate limiting
└── README.md
```

## Load Balancer Details 🔀

The Load Balancer is a FastAPI application that distributes incoming requests across multiple backend servers with intelligent health checking and monitoring.

### Key Features

- **Smart Request Distribution**: Routes requests to healthy backends only
- **Dual Health Checking mechanisms**:
  - **Active Health Checks**: Periodically health-check backends (default every 5 seconds)
  - **Passive Health Checks**: Detect failures based on actual request traffic
- **Configurable Thresholds**:
  - Failure threshold: Number of failed requests to mark backend as unhealthy
  - Success threshold: Number of successful requests to mark backend as healthy
- **Request Tracking**: Each request gets a unique ID for tracking across systems
- **Comprehensive Metrics**: Prometheus-compatible metrics including:
  - Total requests
  - Request duration
  - Proxy retries and failures
  - Backend health status
  - Consecutive failures/successes per backend
  - Passive failure counts

### Endpoints

- **`GET /lb/health`**: Get load balancer and backend health status
- **`GET /lb/metrics`**: Get Prometheus metrics in text format
- **`/{path}`**: Catch-all route that proxies requests to healthy backends

### Configuration

The Load Balancer uses environment variables or `.env` file:

```env
APP_NAME=Load Balancer
APP_HOST=0.0.0.0
APP_PORT=8080
LOG_LEVEL=INFO

# Backends to distribute traffic to
BACKENDS=["http://127.0.0.1:9001", "http://127.0.0.1:9002", "http://127.0.0.1:9003"]

# Health checking
HEALTH_CHECK_INTERVAL=5
HEALTH_FAILURE_THRESHOLD=3
HEALTH_SUCCESS_THRESHOLD=2
PASSIVE_FAILURE_THRESHOLD=2

# Rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60
GLOBAL_MAX_CONCURRENT_REQUESTS=100
```

### Running the Load Balancer

```bash
cd LoadBalancer
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

### Example: Checking Load Balancer Status

```bash
curl http://127.0.0.1:8080/lb/health
```

Response:

```json
{
  "load_balancer": "healthy",
  "configured_backends": ["http://127.0.0.1:9001", "http://127.0.0.1:9002", "http://127.0.0.1:9003"],
  "backends": {
    "http://127.0.0.1:9001": {
      "healthy": true,
      "consecutive_failures": 0,
      "consecutive_successes": 5,
      "passive_failures": 0
    },
    ...
  }
}
```

## Authentication Endpoints 🌐

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

## Installation & Running 🛠️

### General Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/RajChandan/API.git
   cd API
   ```

2. Install dependencies (root level):
   ```bash
   pip install -r requirements.txt
   ```

### Running Standalone Projects

Each file in this project is an independent FastAPI project. Choose one to run:

```bash
# Root level projects
uvicorn main:app --reload              # Main example
uvicorn cookie:app --reload            # Cookie handling
uvicorn jwt_main:app --reload          # JWT authentication
uvicorn pagination:app --reload        # Pagination example
uvicorn rate_limiter:app --reload      # Rate limiting demo
```

### Running the Load Balancer

```bash
cd LoadBalancer
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Then run the backend servers (in separate terminals):

```bash
# Terminal 1
python LoadBalancer/backend1.py

# Terminal 2
python LoadBalancer/backend2.py

# Terminal 3
python LoadBalancer/backend3.py
```

### Running Authentication Systems

```bash
# Basic Authentication
cd Auth
uvicorn basic_auth_api:app --reload

# JWT Authentication
uvicorn jwt_main:app --reload
```

### Accessing APIs

- **Standalone Projects**: http://127.0.0.1:8000/docs
- **Load Balancer**: http://127.0.0.1:8080/docs
- **Load Balancer Health**: http://127.0.0.1:8080/lb/health
- **Load Balancer Metrics**: http://127.0.0.1:8080/lb/metrics

## Contributing 🤝

Contributions are welcome! Please fork the repository and create a pull request with your changes.
