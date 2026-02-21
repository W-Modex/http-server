# HTTP Server (C, Linux, poll-based)

A low-level HTTPS web server written in C from scratch to understand
networking, concurrency, authentication, and backend infrastructure.

Built without frameworks — implements HTTP parsing, routing, TLS,
sessions, CSRF protection, OAuth, and PostgreSQL persistence.

## Features

- Multi-threaded non-blocking event loop (poll-based)
- HTTP/1.1 request parsing and routing
- Static file serving + MIME resolution
- GET / POST / HEAD support
- HTTPS (TLS via OpenSSL)
- HTTP → HTTPS redirect
- Session-based authentication (cookies)
- CSRF protection (token-based mitigation)
- Google OAuth 2.0 login
- PostgreSQL persistence + SQL migrations

## Architecture

- Event-driven main loop using `poll()`
- Worker thread pool for request handling
- OpenSSL TLS termination
- PostgreSQL backend
- Environment-based configuration

## Quick Start

### Requirements
- Linux
- OpenSSL
- PostgreSQL
- gcc / make

### 1. Clone project
git clone <repo>
cd project

### 2. Generate development TLS certificates
./scripts/devcert.sh

### 3. Configure environment
cp .env.example .env
# edit values (DATABASE_URL, OAuth keys, etc.)

### 4. Run migrations
./migrate.sh

### 5. Start server
./run.sh

Server runs at:
https://localhost:3434

## Configuration

Environment variables are loaded from:

- `.env` (local development)
- `~/.config/modex-http/secrets.env`

Required variables:

- DATABASE_URL
- TLS_CERT_FILE
- TLS_KEY_FILE
- OAUTH_GOOGLE_CLIENT_ID (optional)
- OAUTH_GOOGLE_CLIENT_SECRET (optional)

## Google OAuth Setup

1. Create credentials in Google Cloud Console
2. Add redirect URI:
https://localhost:3434/oauth/google/callback