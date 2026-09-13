# Build from the DauthZ workspace root so the embedded login UI is present:
#   docker build -f dauthz-gate/Dockerfile -t dauthz-gate:local .
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p dauthz-gate

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/dauthz-gate /usr/local/bin/dauthz-gate
VOLUME ["/data"]
EXPOSE 8088
HEALTHCHECK --interval=5s --timeout=3s --retries=60 \
    CMD curl -fsS http://127.0.0.1:8088/dauthz/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/dauthz-gate"]
CMD ["serve"]
