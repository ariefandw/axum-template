# Axum Production Scaffold

A strictly-typed backend scaffold on Axum 0.8, SQLx/PostgreSQL, Tower and OpenAPI.
One binary, one database, no other runtime dependencies.

## Features

- **Authentication** — email/password with Argon2id, and OAuth2 with PKCE for
  Google and GitHub. Sessions are database-backed: signing out, being banned, or
  changing a password revokes access immediately rather than waiting for a token
  to expire. Refresh tokens are opaque, hashed at rest, and rotate on every use,
  with replay of a rotated token revoking the whole session family.
- **Authorization** — `AuthUser`, `AdminUser` and `OptionalAuthUser` extractors.
  Roles are re-read from the database per request, never trusted from the token.
- **Storage** — streaming multipart uploads with content-based type detection,
  per-file ownership and visibility, and genuinely HMAC-signed expiring upload
  and download URLs. Backends sit behind a `StorageBackend` trait.
- **Realtime** — Server-Sent Events fanned out across replicas over PostgreSQL
  `LISTEN`/`NOTIFY`, with dropped events signalled to the client rather than
  silently discarded.
- **Notifications and audit** — an in-app notification feed and an append-only
  audit trail whose immutability is enforced by a database trigger. Both are
  keyset-paginated, so they stay fast as the tables grow.
- **Hardening** — scoped idempotency keys, configurable per-IP rate limits with a
  tighter bucket on credential endpoints, per-account lockout, CSP and
  Permissions-Policy headers, and encryption at rest for third-party tokens.
- **Observability** — `tracing` with request-ID propagation, and Prometheus
  metrics labelled by route template so cardinality stays bounded.
- **Docs** — interactive [Scalar](https://scalar.com/) API reference at `/docs`,
  generated from the code by [utoipa](https://github.com/juhaku/utoipa).

## Quick start

```bash
cp .env.example .env
docker compose up -d postgres mailpit
cargo run
```

Migrations run automatically at startup, before the listener binds, so a fresh
database needs no separate step. Then open <http://127.0.0.1:3000/docs>.

To run the whole stack, API included:

```bash
docker compose --profile app up
```

## Testing

The suite runs against a real PostgreSQL instance — there are no mocked
databases, and `tests/security_regressions.rs` reproduces each vulnerability
found in the security review and asserts it no longer works.

```bash
docker compose up -d postgres
export DATABASE_URL=postgres://postgres:postgrespassword@localhost:5432/axum_template_db
cargo test
```

The same gate CI enforces:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --bin export_openapi   # openapi.json must be current
```

## Configuration

Every setting is documented in [`.env.example`](.env.example). Only two are
required in development:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | Signs access tokens; minimum 32 characters |

### Going to production

Set `APP_ENV=production`. The process then **refuses to start** unless the
settings that are unsafe to default are supplied explicitly:

| Variable | Why it is mandatory |
|---|---|
| `ENCRYPTION_KEY` | Seals stored OAuth tokens. Generate with `openssl rand -base64 32`. Rotating it makes existing stored provider tokens unreadable. |
| `CORS_ALLOWED_ORIGINS` | A wildcard origin policy is refused. |
| `METRICS_TOKEN` | `/metrics` exposes route inventory and traffic volumes. |
| `SMTP_HOST` | Without a mailer, account-recovery email is silently dropped. |

`SMTP_TLS=false` is also refused in production, and HSTS is asserted only there,
so local development is not pinned to an https origin that does not exist.

Two further settings deserve thought:

- `TRUST_PROXY_HEADERS` defaults to `false`. Enable it **only** behind a proxy
  you control: when true, `X-Forwarded-For` decides both the rate-limit bucket
  and the client IP recorded in the audit trail, so an untrusted caller could
  otherwise choose both.
- `UPLOAD_DIR` must be a mounted volume. Container-local storage disappears with
  the container and is invisible to other replicas.

## Architecture

See [AGENTS.md](AGENTS.md) for the security model, middleware ordering, the list
of regression-protected invariants, and what is deliberately not implemented.

## Licence

MIT — see [LICENSE](LICENSE).
