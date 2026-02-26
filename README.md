# HTTP Server (C, Linux, poll-based)

A low-level HTTPS web server written in C from scratch to understand
networking, concurrency, authentication, and backend infrastructure.

Built without frameworks, it implements HTTP parsing, routing, TLS,
sessions, CSRF protection, OAuth, and PostgreSQL persistence.

The project is fully containerized with Docker for easy cross-platform execution.

## Features

- Multi-threaded non-blocking event loop (poll-based)
- HTTP/1.1 request parsing and routing
- Static file serving + MIME resolution
- GET / POST / HEAD support
- HTTPS (TLS via OpenSSL)
- Session-based authentication (cookies)
- CSRF protection (token-based mitigation)
- Google OAuth 2.0 login
- PostgreSQL persistence + SQL migrations
- Dockerized deployment (cross-platform)

## Architecture

- Event-driven main loop using `poll()`
- Worker thread pool for request handling
- OpenSSL TLS termination
- PostgreSQL backend
- Environment-based configuration
- Docker container runtime

## Quick Start (Recommended - Docker)

This is the easiest way to run the server on Linux, Windows, or macOS.

### Requirements

- Docker
- Linux: Docker Engine
- Windows/macOS: Docker Desktop

### 1. Clone project

```
git clone https://github.com/W-Modex/http-server
cd http-server
```

### 2. Configure environment

```
cp .env.example .env
```

Edit `.env` if needed:

- `DATABASE_URL`
- OAuth keys (optional)

Default configuration works out of the box with Docker.

### 3. Run server

```
docker compose up --build
```

### 4. Open in browser

`https://localhost:3434`

Accept the self-signed certificate warning.

## What Docker Runs

- HTTP server container
- PostgreSQL database container
- Automatic SQL migrations on startup

No manual database setup required.

## Configuration

Configuration is loaded from:

- `.env`

### Required Variables

- `DATABASE_URL`
- `TLS_CERT_FILE`
- `TLS_KEY_FILE`

### Optional

- `OAUTH_GOOGLE_CLIENT_ID`
- `OAUTH_GOOGLE_CLIENT_SECRET`
- `OAUTH_GOOGLE_REDIRECT_URI`

## Google OAuth Setup (Optional)

1. Create credentials in Google Cloud Console.
2. Add redirect URI:

```
https://localhost:3434/oauth/google/callback
```

## Manual Build (Linux Only - Optional)

If you want to run without Docker:

### Requirements

- Linux
- OpenSSL
- PostgreSQL
- CMake

```
cmake -S . -B build
cmake --build build
./run.sh
```

Docker is recommended for portability.
