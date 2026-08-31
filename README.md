# Axum 0.8+ Production Scaffold

A robust, strictly-typed backend scaffold built on modern Axum, SQLx PostgreSQL, Tower, and OpenAPI.

## Features

- **Web Framework:** [Axum 0.8+](https://github.com/tokio-rs/axum) with native `{param}` routing syntax and strict JSON extractors.
- **Database:** [SQLx](https://github.com/launchbadge/sqlx) for PostgreSQL with async connection pooling and migrations.
- **Authentication:**
  - Standard email + password registration/login with Argon2 hashing and JWT token issuance.
  - Social OAuth2 login flows (Google & GitHub).
  - Strongly typed `AuthUser` extractor for route authorization guards.
- **Rate Limiting:** IP-based rate limiting via `tower_governor`.
- **API Documentation:** Interactive [Scalar](https://scalar.com/) docs generated via [utoipa](https://github.com/juhaku/utoipa) served at `/docs`.
- **Observability:** `tracing` + `tracing-subscriber` + `tower-http` TraceLayer and UUID request ID propagation (`x-request-id`).
- **Resilience:** Graceful shutdown with signal handling (`SIGINT`/`SIGTERM`) and strict request timeouts.

## Quick Start

### 1. Configure Environment
```bash
cp .env.example .env
```

### 2. Run Database Migrations
Make sure PostgreSQL is running, then run migrations:
```bash
cargo install sqlx-cli --no-default-features --features postgres
sqlx migrate run
```

### 3. Start the Server
```bash
cargo run
```

Access the interactive API documentation at `http://127.0.0.1:3000/docs`.
