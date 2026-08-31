# Multi-stage Dockerfile for Minimal Production Image
# 1. Chef Planner Stage
FROM lukemathwalker/cargo-chef:latest-rust-1.85-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# 2. Builder Stage (Cached Dependency Layer)
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin axum-template

# 3. Minimal Distroless Runtime Stage
FROM alpine:3.21 AS runtime
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/target/release/axum-template /usr/local/bin/axum-template
COPY migrations /app/migrations

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000
EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/axum-template"]
