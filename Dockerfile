FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY platform-proto /src/platform-proto
COPY auth-service /src/auth-service
RUN cargo build --locked --release --manifest-path /src/auth-service/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 app
COPY --from=build /src/auth-service/target/release/auth-service /usr/local/bin/auth-service
USER app
EXPOSE 50051 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:8081/health/live || exit 1
ENTRYPOINT ["/usr/local/bin/auth-service"]
