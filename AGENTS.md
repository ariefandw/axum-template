# Axum Production Template - Architecture & Agent Manifesto

> **Mission:** Protect production, eliminate technical debt, prevent "masuk angin" bloatware, and maintain high-performance, strictly-typed Rust backend excellence.

---

## 1. Core Engineering Principles

1. **Zero Bloat ("No Masuk Angin" Engineering):**
   - No unnecessary abstraction layers, dynamic document proxies, or 12-container microservice clusters for basic features.
   - Every system feature is native, in-process, compile-time verified, and runs under 20MB RAM.
2. **Strict Compile-Time Correctness:**
   - Single source of truth: Rust structs + `utoipa` + `serde` + `sqlx`.
   - Never write redundant types. One struct derives JSON serialization, database row mapping, validation, and OpenAPI 3.1 documentation.
3. **Hierarchical Route Composition (Zero Hardcoded Prefixes):**
   - Handlers define relative paths (`#[utoipa::path(post, path = "/sign-up/email")]`).
   - Routers compose hierarchically using `OpenApiRouter::nest("/api/v1", v1_router)`.
4. **PostgreSQL & UUID v7 Standard:**
   - All primary keys across all tables are sortable `Uuid::now_v7()`.
   - Schema matches Better Auth conventions (`users`, `accounts`, `verifications`, `notifications`, `audit_logs`).
5. **Standard API Contract:**
   - Success: `ApiResponse<T>` -> `{ "success": true, "data": T, "meta": ... }`
   - Failure: `ApiErrorResponse` -> `{ "success": false, "error": { "code": "...", "message": "...", "details": ... } }`

---

## 2. System Architecture & Capabilities

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          Axum 0.8+ HTTP API                            │
│  - Smart-IP Rate Limiting (tower_governor)                              │
│  - Idempotency Replay Protection (Idempotency-Key)                     │
│  - Prometheus Metrics Exporter (/metrics)                              │
│  - Strict Security Headers (HSTS, CSP, X-Frame-Options)                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌───────────────┐          ┌─────────────────┐          ┌─────────────────┐
│ /api/v1/auth  │          │  /api/v1/users  │          │  /api/v1/files  │
│ - Email Auth  │          │ - /me (Profile) │          │ - Stream Upload │
│ - Google/GH   │          │ - /password     │          │ - Presigned URL │
│ - BetterAuth  │          │ - Admin List    │          │ - Safe Download │
│   RPC Aliases │          │   (AdminUser)   │          │ - Delete File   │
└───────┬───────┘          └────────┬────────┘          └────────┬────────┘
        │                           │                            │
        └───────────────────────────┼────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌──────────────────┐       ┌─────────────────┐          ┌─────────────────┐
│ /api/v1/realtime │       │/notifications   │          │/api/v1/audit-logs│
│ - Tokio SSE      │       │- In-App Feed    │          │- Immutable Log  │
│   Stream         │       │- Mark Read      │          │- Admin RBAC     │
│ - 15s Heartbeat  │       │- SSE Trigger    │          │  (AdminUser)    │
└──────────────────┘       └─────────────────┘          └─────────────────┘
```

---

## 3. Directory Layout

```text
src/
├── bin/
│   └── export_openapi.rs       # Standalone OpenAPI JSON exporter CLI
├── config/                     # Strongly-typed environment configuration (AppConfig)
├── error/                      # Unified error handling & standard JSON envelopes
├── middleware/
│   ├── auth.rs                 # JWT AuthUser & AdminUser RBAC extractors
│   ├── idempotency.rs          # Mutation replay protection middleware
│   ├── metrics.rs              # Prometheus metrics recorder middleware
│   ├── rate_limit.rs           # Smart-IP rate limiter (tower_governor)
│   └── security_headers.rs     # Security headers injector
├── models/
│   ├── events.rs               # Realtime, Notifications, and AuditLog DTOs
│   ├── pagination.rs           # Standard PageParams, PageMeta, CursorParams
│   ├── upload.rs               # Multipart & Presigned upload DTOs
│   └── user.rs                 # User, Account, Verification, Auth DTOs
├── routes/
│   ├── health.rs               # /health and /metrics endpoints
│   ├── mod.rs                  # Root router merging health & /api/v1
│   └── v1/
│       ├── audit.rs            # Compliance audit log endpoints (Admin only)
│       ├── auth.rs             # Better Auth compatible auth suite & RPC aliases
│       ├── files.rs            # Streaming multipart & presigned file storage
│       ├── mod.rs              # v1 sub-router composition
│       ├── notifications.rs    # In-app notifications feed
│       ├── realtime.rs         # Server-Sent Events (SSE) stream
│       └── users.rs            # User profile management & RBAC admin query
├── services/
│   ├── audit.rs                # Async audit logger
│   ├── auth.rs                 # Argon2id hashing, JWT, Better Auth business logic
│   ├── mail.rs                 # Async transactional SMTP mailer (lettre)
│   ├── notification.rs         # In-app notification engine with realtime push
│   ├── oauth.rs                # Google & GitHub OAuth2 state/code exchange
│   └── storage.rs              # Streaming multipart file I/O & presigned URLs
├── state/                      # Global AppState (Db pool, Config, Realtime broadcast)
├── lib.rs                      # ApiDoc OpenAPI declaration & app factory
└── main.rs                     # Tokio server entrypoint
```

---

## 4. Key Agent Instructions & Rules

1. **Keep It DRY:** When adding aliases or alternative API conventions (e.g. Better Auth RPC vs REST), always delegate to the same underlying `Service` method. Never duplicate database queries or business logic.
2. **Preserve Hierarchical Routing:** Always register new handlers relative to their sub-router (`routes/v1/{module}.rs`) and compose with `OpenApiRouter::nest()`.
3. **Verify All 3 Checks Before Finishing Any Task:**
   - `cargo check` (Zero warnings/errors)
   - `cargo test` (All integration tests green)
   - `cargo run --bin export_openapi` (Keep `openapi.json` synchronized)
