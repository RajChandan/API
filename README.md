# 🚦 Rate Limiter API

This project implements various **rate-limiting strategies** using FastAPI and Redis. Rate limiting is a technique used to control the number of requests a client can make to an API within a specific time window. The API supports multiple rate-limiting algorithms, including **Fixed Window**, **Sliding Log**, **Sliding Counter**, **Token Bucket**, and **Leaky Bucket**.

---

## ✨ Features

- 🕒 **Fixed Window Rate Limiter**: Simple counter-based rate limiting for fixed time windows.
- 📜 **Sliding Log Rate Limiter**: Tracks individual request timestamps for precise rate limiting.
- 📊 **Sliding Counter Rate Limiter**: Approximates sliding windows using weighted counters.
- 🪣 **Token Bucket Rate Limiter**: Allows bursts of requests with a refill rate.
- 🚰 **Leaky Bucket Rate Limiter**: Smooths out request bursts by "leaking" requests at a fixed rate.
- 🛠️ **Redis Integration**: Uses Redis as the backend for efficient request tracking.
- ⚙️ **Customizable**: Configure limits, time windows, refill rates, and leak rates via query parameters.

---

## 🌐 Endpoints

### 1. **Meta Endpoints**

- **`GET /`**: Provides metadata about the API and available rate-limiting strategies.
- **`GET /whoami`**: Returns information about the client (IP, port, and API key).

### 2. **Rate Limiting Strategies**

| **Endpoint**           | **Description**                                            | **Query Parameters**                                                |
| ---------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------- |
| `GET /fixed`           | Implements the **Fixed Window** rate-limiting strategy.    | `limit` (max requests), `window` (time window in seconds).          |
| `GET /sliding_log`     | Implements the **Sliding Log** rate-limiting strategy.     | `limit` (max requests), `window` (time window in seconds).          |
| `GET /sliding_counter` | Implements the **Sliding Counter** rate-limiting strategy. | `limit` (max requests), `window` (time window in seconds).          |
| `GET /token_bucket`    | Implements the **Token Bucket** rate-limiting strategy.    | `capacity` (bucket size), `refill_rate` (tokens added per second).  |
| `GET /leaky_bucket`    | Implements the **Leaky Bucket** rate-limiting strategy.    | `capacity` (bucket size), `leak_rate` (requests leaked per second). |

---
