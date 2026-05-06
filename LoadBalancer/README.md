# FastAPI Load Balancer / API Gateway

This is a fast, asynchronous API Gateway and Load Balancer built with FastAPI. It routes requests to backend services, supports load balancing, health checks, circuit breaking, and JWT authentication.

## Project Structure

*   `app/`: Core gateway application code.
    *   `main.py`: FastAPI application entry point.
    *   `config.py`: Pydantic settings and configuration validation.
    *   `gateway.yaml`: Configuration for routing and service policies.
*   `.env`: Environment variables (overrides defaults).
*   `*backend*.py`: Dummy backend services for testing the load balancer.

## Configuration Setup

1.  **Environment Variables (`.env`)**
    Ensure your `.env` file located in the root directory is correctly set up. A critical configuration is the path to your gateway yaml file:
    ```ini
    GATEWAY_CONFIG_FILE=app/gateway.yaml
    ```
    *Note: The path should be relative to the root folder where you start the application.*

2.  **Routing Configuration (`app/gateway.yaml`)**
    This file defines your downstream services, their prefixes, and the upstream backend URLs.

## Running the Application

1.  **Start the Backend Services**
    In separate terminal windows, start the mock backends to receive traffic:
    ```bash
    python order_backend1.py
    python order_backend2.py
    # ... and any other backends configured in gateway.yaml
    ```

2.  **Start the API Gateway**
    From the root directory of the project, run the FastAPI gateway application:
    ```bash
    uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
    ```

## Features

*   **Dynamic Routing:** Based on path prefixes.
*   **Load Balancing:** Distributes requests among healthy backends.
*   **Health Checks:** Automatically monitors backend health and ejects failing nodes.
*   **Authentication:** JWT-based protection for configured routes.
*   **Timeouts & Retries:** Configurable connection, read, and write timeouts with retry mechanisms.



                                   ┌──────────────────────┐
                                   │      CLIENTS         │
                                   │  Web / Mobile / API  │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                         ┌────────────────────────────────────┐
                         │         FASTAPI API GATEWAY        │
                         │                                    │
                         │  ┌──────────────────────────────┐  │
                         │  │         Routing Layer        │  │
                         │  │  /users  → user-service      │  │
                         │  │  /orders → order-service     │  │
                         │  └──────────────┬───────────────┘  │
                         │                 │                  │
                         │                 ▼                  │
                         │  ┌──────────────────────────────┐  │
                         │  │       Auth Layer             │  │
                         │  │                              │  │
                         │  │  JWT Validation              │  │
                         │  │  Role/Scope Authorization    │  │
                         │  │  Identity Header Injection   │  │
                         │  └──────────────┬───────────────┘  │
                         │                 │                  │
                         │                 ▼                  │
                         │  ┌──────────────────────────────┐  │
                         │  │      Policy Engine           │  │
                         │  │                              │  │
                         │  │  Allowed Methods             │  │
                         │  │  Strip Prefix                │  │
                         │  │  Body Size Limits            │  │
                         │  │  Retry Policy                │  │
                         │  │  Circuit Breaker             │  │
                         │  │  Rate Limiting               │  │
                         │  └──────────────┬───────────────┘  │
                         │                 │                  │
                         │                 ▼                  │
                         │  ┌──────────────────────────────┐  │
                         │  │      Load Balancer           │  │
                         │  │                              │  │
                         │  │  Round Robin Selection       │  │
                         │  │  Health Checks               │  │
                         │  │  Backend Ejection            │  │
                         │  └──────────────┬───────────────┘  │
                         │                 │                  │
                         │                 ▼                  │
                         │  ┌──────────────────────────────┐  │
                         │  │      Shared HTTP Clients     │  │
                         │  │  Persistent Connection Pool  │  │
                         │  └──────────────┬───────────────┘  │
                         └─────────────────┼──────────────────┘
                                           │
               ┌───────────────────────────┼───────────────────────────┐
               │                           │                           │
               ▼                           ▼                           ▼

   ┌──────────────────┐      ┌──────────────────┐       ┌──────────────────┐
   │  USER BACKEND 1  │      │  USER BACKEND 2  │       │ ORDER BACKEND 1  │
   │  localhost:9001  │      │  localhost:9002  │       │ localhost:9011   │
   └──────────────────┘      └──────────────────┘       └──────────────────┘
                                                                  │
                                                                  ▼
                                                    ┌──────────────────┐
                                                    │ ORDER BACKEND 2  │
                                                    │ localhost:9012   │
                                                    └──────────────────┘



─────────────────────────────────────────────────────────────────────────────
                        SUPPORTING INFRASTRUCTURE
─────────────────────────────────────────────────────────────────────────────

               ┌────────────────────────────────────────┐
               │                REDIS                   │
               │                                        │
               │  Distributed Rate Limiting             │
               │  Shared State Across Workers           │
               │  Shared State Across Containers        │
               └────────────────────────────────────────┘


               ┌────────────────────────────────────────┐
               │          OBSERVABILITY                 │
               │                                        │
               │  JSON Structured Logs                  │
               │  Prometheus Metrics                    │
               │  Request Duration Metrics              │
               │  Backend Health Metrics                │
               │  Retry Metrics                         │
               │  Circuit Breaker Metrics               │
               └────────────────────────────────────────┘


─────────────────────────────────────────────────────────────────────────────
                            CONFIGURATION
─────────────────────────────────────────────────────────────────────────────

               ┌────────────────────────────────────────┐
               │              gateway.yaml              │
               │                                        │
               │  Services                              │
               │  Routes                                │
               │  Policies                              │
               │  Retry Config                          │
               │  Circuit Breaker Config                │
               │  Rate Limit Config                     │
               │  Auth Config                           │
               └────────────────────────────────────────┘


─────────────────────────────────────────────────────────────────────────────
                           CURRENT FEATURES
─────────────────────────────────────────────────────────────────────────────

✅ Dynamic service routing
✅ YAML-based config
✅ JWT authentication
✅ Role/scope authorization
✅ Admin endpoint protection
✅ Shared async HTTP clients
✅ Health checks
✅ Circuit breaker
✅ Retry policy
✅ Strip prefix/path rewrite
✅ Redis distributed rate limiting
✅ Structured JSON logging
✅ Prometheus metrics
✅ Round-robin balancing
✅ Backend health tracking
✅ Graceful startup/shutdown