# syntax=docker/dockerfile:1.7
FROM rust:1.94.0-bookworm@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f AS builder

WORKDIR /build
COPY rust/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --locked -p stirling-ai-engine --bins \
    && cp target/release/stirling-ai-engine /tmp/stirling-ai-engine \
    && cp target/release/migrate-sqlite-vec /tmp/migrate-sqlite-vec

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system stirling \
    && useradd --system --gid stirling --home-dir /app --shell /usr/sbin/nologin stirling \
    && install -d -o stirling -g stirling /app/data

COPY --from=builder /tmp/stirling-ai-engine /usr/local/bin/stirling-ai-engine
COPY --from=builder /tmp/migrate-sqlite-vec /usr/local/bin/migrate-sqlite-vec

WORKDIR /app
ENV STIRLING_ENGINE_HOST=0.0.0.0 \
    STIRLING_ENGINE_PORT=5001

USER stirling
EXPOSE 5001

CMD ["/usr/local/bin/stirling-ai-engine"]
