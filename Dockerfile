# syntax=docker/dockerfile:1
# Multi-stage build producing a minimal, non-root runtime image.

FROM lukemathwalker/cargo-chef:latest-rust-1.90-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin axum-template

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -S app -g 10001 \
    && adduser -S app -G app -u 10001 -h /app

WORKDIR /app
COPY --from=builder --chown=app:app /app/target/release/axum-template /usr/local/bin/axum-template
# Migrations are embedded in the binary by sqlx::migrate!; this copy is for
# operators running sqlx-cli against the image.
COPY --chown=app:app migrations /app/migrations

# Uploads must be a mounted volume in any real deployment: container-local
# storage disappears with the container and is invisible to other replicas.
RUN mkdir -p /app/uploads && chown app:app /app/uploads
VOLUME ["/app/uploads"]

# Never run as root: a container escape should not start from uid 0.
USER app:app

ENV SERVER_HOST=0.0.0.0 \
    SERVER_PORT=3000 \
    APP_ENV=production \
    UPLOAD_DIR=/app/uploads
EXPOSE 3000

# Readiness, not liveness: the orchestrator should pull a pod out of rotation
# for a database blip rather than restart it.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/health/ready || exit 1

ENTRYPOINT ["/usr/local/bin/axum-template"]
