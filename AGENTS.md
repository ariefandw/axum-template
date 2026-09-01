# Axum Production Template — Architecture & Agent Manifesto

> **Mission:** protect production, eliminate technical debt, prevent bloatware, and
> keep a high-performance, strictly-typed Rust backend honest about what it does.

---

## 0. The prime directive: claims must be executable

This template previously documented a CSP it never sent, an "immutable" audit
table nothing protected, and a presigned-URL feature that returned an unsigned
static path. A security review found forty defects, five of them critical, and
the gap between documentation and behaviour was the common thread.

So the first rule outranks every other rule in this file:

**Never describe a capability here that the code does not implement.** If a
feature is aspirational, put it in §7 and mark it as such. If you remove a
capability, remove its claim in the same commit. A reader must be able to take
any sentence in this document and find the code that makes it true.

Corollary: **a security property needs a test that fails without it.** Every
item in §4 has a regression test. Adding a security control without one is
incomplete work.

---

## 1. Core engineering principles

1. **Zero bloat.** No unnecessary abstraction layers, no dynamic document
   proxies, no twelve-container cluster for basic features. One binary and one
   PostgreSQL database is the entire runtime dependency set — realtime fan-out
   uses `LISTEN`/`NOTIFY` and idempotency uses a table, rather than adding Redis.
2. **Strict compile-time correctness.** One struct derives JSON serialization,
   row mapping, validation, and OpenAPI documentation. Never write redundant
   types. Joined queries get a purpose-built `FromRow` row struct rather than a
   tuple of structs, which sqlx cannot map.
3. **Hierarchical route composition.** Handlers declare relative paths; routers
   compose with `OpenApiRouter::nest`. No hardcoded prefixes.
4. **PostgreSQL and UUIDv7.** All primary keys are sortable `Uuid::now_v7()`.
   UUIDv7 is time-ordered and therefore *guessable*: it is an identifier, never a
   capability. Anything reachable by ID needs an authorization check.
5. **Standard API contract.**
   - Success: `{ "success": true, "data": T, "meta": ... }`
   - Failure: `{ "success": false, "error": { "code", "message", "details" } }`
6. **Development defaults must not reach production.** Anything convenient
   locally — open CORS, unauthenticated metrics, a mailer that logs instead of
   sending, an encryption key derived from `JWT_SECRET` — is a hard startup error
   when `APP_ENV=production`. See `AppConfig::load_from_env`.

---

## 2. Security model

The template's security rests on eight decisions. Change any of them only
deliberately, and update the regression tests in the same commit.

### 2.1 Sessions are the source of truth, not the token

The access token is a short-lived (15 minute) JWT naming a **session row**. Every
authenticated request resolves that row, joined against the user, and rejects it
if the session was revoked or expired or the user was banned or deleted. That
round trip is what makes a ban, a sign-out, a password change, or a role change
take effect immediately.

Refresh tokens are opaque, stored only as SHA-256 digests, and **rotate on every
use**. The superseded digest is retained in `previous_token_hash`: presenting an
already-rotated token is the signature of a stolen token being replayed, and it
revokes every session for that user.

Never read `role` or `banned` from token claims for an authorization decision.
`AuthUser` and `AdminUser` already carry the database's answer.

### 2.2 Recovery tokens are purpose-scoped, hashed, and single-use

`verifications` rows carry an explicit `purpose` (`email_verify` or
`password_reset`), enforced by a `CHECK` constraint and filtered on at
consumption. Tokens are stored only as digests, and consumption is a single
atomic `UPDATE ... RETURNING`, so a token cannot be redeemed twice concurrently.

Never add a token type without a purpose value. An unscoped token is a
cross-endpoint replay waiting to happen.

### 2.3 Every object has an owner

Uploads get a `files` row carrying `owner_id` and `visibility`. Reads and deletes
authorize against that row. Callers who may not see a file receive `404`, not
`403`, so the endpoint cannot be used to enumerate IDs.

Stored MIME types come from **sniffing the leading bytes**, never from the
supplied filename or `Content-Type`. Storage keys are generated and validated
against a strict character allowlist, so traversal is impossible by construction
rather than by blocklist.

### 2.4 Secrets never reach a log line

Credentials are wrapped in `crypto::Secret`, whose `Debug` and `Display` both
redact; the only way out is `.expose()`, which makes every disclosure greppable.
`AppConfig`'s hand-written `Debug` redacts the key material it holds directly.

Never log a recovery token, a rendered mail body, a session token, or a
configuration field holding credentials. Log identifiers and event names.

### 2.5 A machine credential is narrower than the human it belongs to

An API key is not a password. It sits in CI configuration and on servers, it is
long-lived, and it leaks in ways interactive credentials do not. Three rules keep
a leaked key from becoming permanent control:

* **Scopes are enforced, not decorative.** `Credential::require_scope` gates every
  resource route. A key declaring `["users:read"]` cannot write. Unknown scope
  names are rejected at creation rather than dropped, and stored scopes that
  cannot be parsed resolve to *no* authority rather than wildcard.
* **`*` does not include `admin`.** Reaching an administrative route needs both
  the account's `admin` role and a key issued explicitly with the `admin` scope.
* **Account lifecycle is closed to keys entirely, at any scope.** Changing a
  password, deleting the account, revoking sessions, and minting further keys all
  require `SessionUser`. Without this, revoking a leaked key is futile — the
  attacker has already minted their own.

`SessionUser` exists precisely so these routes get a real `session_id`. The
previous implementation handed API keys `Uuid::nil()`, which matched no row and
made session-scoped operations quietly appear to succeed.

### 2.6 Tenancy reaches the data plane

An organization is a boundary, not a directory entry. `files` and `notifications`
carry `org_id`, and membership is what grants access to them:

* members of an organization can read its files; non-members get `404`, not `403`
* `admin` or `owner` is required to delete them — reading a tenant's data is not
  the same as destroying it
* uploading into an organization checks membership *before* any bytes are written
* the notification feed's `org_id` filter is membership-checked, never trusted

Never add a tenant-scoped table without deciding, in the same commit, which
membership level reads it and which one writes it. A scoping column that no code
consults is worse than none, because the next reader will trust it.

### 2.7 Storage backends never see an authorization decision

`StorageService` owns validation — size caps, content sniffing, ownership and org
membership — and hands a finished object to a `StorageBackend`. A backend only
moves bytes. That split is why swapping local disk for S3 changes where files
live without touching a single access check, and why the same generated-key
allowlist that stops `../` on disk also stops key injection against a bucket.

Never let a caller supply a storage key, and never put an authorization decision
inside a backend.

### 2.8 Untrusted input never picks its own bucket

`X-Forwarded-For` is honoured only when `TRUST_PROXY_HEADERS=true`, because a
caller who chooses their apparent IP also chooses their rate-limit bucket and the
client IP recorded in the audit trail. The default is the peer address.

Idempotency keys are scoped to `(identity, method, path, body hash, key)`. A key
alone must never address a cache entry: that let one caller receive another's
response, access token included.

---

## 3. System architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                            Axum 0.8 HTTP API                             │
│  outermost → innermost                                                   │
│    request-id → trace → outcome counter → timeout → body limit → CORS    │
│    → global rate limit → security headers → idempotency                  │
│    → [routing] → route metrics (MatchedPath) → auth rate limit → handler │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌───────────────┐          ┌─────────────────┐          ┌──────────────────┐
│ /api/v1/auth  │          │  /api/v1/users  │          │  /api/v1/files   │
│ - Email auth  │          │ - /me profile   │          │ - Streaming      │
│ - Sessions +  │          │ - /me/password  │          │   upload + sniff │
│   refresh     │          │   (SessionUser) │          │ - Signed URLs    │
│ - OAuth+PKCE  │          │ - Admin list    │          │ - Owner + org    │
│ - Scoped M2M  │          │   (AdminUser)   │          │   ACLs           │
│   API keys    │          │                 │          │ - /org/{id} list │
└───────┬───────┘          └────────┬────────┘          └────────┬─────────┘
        └───────────────────────────┼────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌──────────────────┐       ┌─────────────────┐          ┌──────────────────┐
│ /api/v1/realtime │       │ /notifications  │          │ /api/v1/audit-   │
│ - SSE stream     │       │ - Cursor feed   │          │   logs           │
│                  │       │ - Org filter    │          │                  │
│ - Cross-replica  │◀──────│ - Publishes via │          │ - Append-only    │
│   via LISTEN/    │       │   pg_notify     │          │   (DB trigger)   │
│   NOTIFY         │       │ - Mark read     │          │ - Admin RBAC     │
│ - Lag signalled  │       │                 │          │ - Keyset paging  │
└──────────────────┘       └─────────────────┘          └──────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │    PostgreSQL     │
                          │ users, accounts,  │
                          │ sessions, files,  │
                          │ verifications,    │
                          │ oauth_requests,   │
                          │ idempotency_keys, │
                          │ notifications,    │
                          │ audit_logs, apps, │
                          │ organizations,    │
                          │ org_members,      │
                          │ api_keys          │
                          └───────────────────┘
```

**Middleware order matters.** Metrics are split in two on purpose: the route
metric runs *inside* routing via `route_layer`, so `MatchedPath` is available and
labels stay bounded by the route template; a separate outermost counter catches
rate-limit rejections and timeouts, which never reach a route. Never label a
metric with `req.uri().path()` — that is an unbounded, anonymously-driven memory
leak in the registry.

---

## 4. Regression-protected invariants

Each of these has a test that fails if the property is lost. Do not weaken one
without deleting its test, and do not delete its test.

| Invariant | Test |
|---|---|
| An idempotency key cannot replay another caller's response | `idempotency_key_cannot_replay_another_users_response` |
| A genuine retry still replays | `idempotency_key_replays_the_same_callers_identical_request` |
| An email-verification token cannot reset a password | `email_verification_token_cannot_reset_a_password` |
| A reset token works once, for its own purpose only | `password_reset_token_works_for_its_own_purpose` |
| Private files resist anonymous read and cross-user delete | `files_are_not_readable_or_deletable_by_strangers` |
| Banning invalidates a live token | `banning_a_user_invalidates_their_live_token` |
| Sign-out revokes immediately | `signing_out_revokes_the_access_token_immediately` |
| Demotion takes effect without waiting for expiry | `demoting_an_admin_takes_effect_without_waiting_for_expiry` |
| Refresh tokens rotate, and replay revokes the family | `refresh_rotates_the_token_and_detects_replay` |
| Metric cardinality does not grow with distinct paths | `metric_labels_do_not_grow_with_distinct_paths` |
| Unknown and known accounts are indistinguishable | `unknown_and_known_accounts_return_the_same_rejection` |
| Audit rows cannot be updated or deleted | `audit_log_rows_cannot_be_modified_or_deleted` |
| Uploads are typed by content, not filename | `uploads_are_typed_by_content_not_by_filename` |
| Signed URLs grant access and reject tampering | `signed_download_urls_grant_access_and_reject_tampering` |
| Production refuses unsafe defaults | `config::tests::production_refuses_unsafe_defaults` |
| The config struct is safe to log | `config::tests::debug_output_contains_no_secrets` |
| An API key's declared scopes actually restrict it | `declared_scopes_actually_restrict_the_key` |
| A `*` key does not reach admin routes | `wildcard_keys_do_not_include_admin` |
| A key cannot change the password, delete the account, revoke sessions, or mint keys | `api_keys_cannot_perform_account_lifecycle_operations` |
| An unknown scope name is rejected, not dropped | `unknown_scopes_are_rejected_at_creation` |
| Scoping never narrows an interactive session | `sessions_are_unaffected_by_scoping` |
| Org members can read their tenant's files | `org_members_can_read_their_organizations_files` |
| Plain members cannot delete tenant files | `plain_members_cannot_delete_organization_files` |
| Outsiders cannot upload into an organization | `outsiders_cannot_upload_into_an_organization` |
| The org file listing is membership-gated | `org_file_listing_is_membership_gated` |
| The notification org filter is membership-checked | `notification_org_filter_requires_membership` |
| A backend rejects any key it did not generate | `s3_rejects_keys_that_are_not_generated` |
| Objects round-trip through S3 unchanged | `s3_round_trips_an_object` |
| Presigned URLs bypass this service | `s3_presigned_urls_point_at_object_storage` |

---

## 5. Directory layout

```text
src/
├── bin/export_openapi.rs   # OpenAPI JSON exporter; CI checks the spec is current
├── config/                 # Typed configuration + production safety gates
├── crypto/                 # Secret wrapper, hashing, HMAC signing, AEAD at rest
├── error/                  # Error enum and the standard JSON envelopes
├── middleware/
│   ├── auth.rs             # Credential, AuthUser / AdminUser / SessionUser / OptionalAuthUser
│   ├── idempotency.rs      # Scoped, Postgres-backed replay protection
│   ├── metrics.rs          # MatchedPath route metrics + outermost outcome counter
│   ├── rate_limit.rs       # Configurable limits and proxy-header trust
│   └── security_headers.rs # CSP, Permissions-Policy, conditional HSTS
├── models/                 # Request/response DTOs, row structs, pagination
├── routes/                 # health + v1/{auth,users,files,notifications,realtime,audit}
├── services/
│   ├── storage_backend/    # StorageBackend trait + local disk and S3 impls
│   ├── api_key.rs          # M2M key issuance, scoped resolution, throttled last-use
│   ├── audit.rs            # Append-only audit trail
│   ├── auth.rs             # Argon2id, sessions, recovery tokens, lockout
│   ├── mail.rs             # SMTP with TLS and credentials
│   ├── notification.rs     # In-app notifications, published via pg_notify
│   ├── oauth.rs            # OAuth2 + PKCE, server-side state validation
│   ├── org.rs              # Apps, organizations, and OrgRole membership checks
│   ├── realtime.rs         # LISTEN/NOTIFY bridge and publisher
│   └── storage.rs          # StorageBackend trait, sniffing, signed URLs
├── state/                  # AppState (pool, config, realtime channel, metrics)
├── lib.rs                  # OpenAPI declaration and app factory
└── main.rs                 # Entrypoint: migrations, listener task, cleanup loop
```

---

## 6. Rules for agents working here

1. **Keep it DRY.** Alternative API conventions (Better Auth RPC vs REST)
   delegate to the same service method. Never duplicate a query or a rule.
2. **Preserve hierarchical routing.** Register handlers on their sub-router and
   compose with `nest`.
3. **Authorize at the row, not the route.** A handler that loads something by ID
   must check who is asking before returning it.
4. **Add a migration, never edit a released one.** sqlx checksums applied
   migrations; editing one breaks every existing deployment.
5. **Run the full gate before finishing any task:**
   ```bash
   cargo fmt --all --check
   cargo clippy --all-targets -- -D warnings   # zero warnings, not "few"
   cargo test                                   # requires DATABASE_URL
   cargo run --bin export_openapi               # keep openapi.json in sync
   ```
6. **Tests talk to a real database.** `TestApp::spawn` connects and migrates.
   Never reintroduce a lazy pool that lets a test pass without touching
   PostgreSQL — that is how the original suite reported 8/8 green while covering
   none of the business logic.

---

## 7. Deliberately not implemented

Recorded so nobody mistakes absence for oversight.

- **A fully declarative permission model.** Apps, organizations, `OrgRole`
  membership, and org-scoped files and notifications are implemented. What is not
  is a general permission grammar (`read("team:x:role")` applied uniformly to
  arbitrary resources) — authorization is currently expressed per resource in
  code. Adding a tenant-scoped table means writing its checks explicitly.
- **Outbound webhooks.**
- **Per-tenant quotas, usage metering, and billing hooks.** Nothing counts or
  caps what an organization consumes.
- **Dynamic collections and a functions runtime.** Deliberately rejected, not
  merely absent: dynamic documents would give up the compile-time typing that is
  this template's main advantage, and a functions runtime is exactly the
  container cluster §1 rules out.
