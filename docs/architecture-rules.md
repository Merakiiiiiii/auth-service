# Auth service architecture rules

These rules are executable through `scripts/check_architecture.py`.

## Size limits

- Rust source file: at most 250 lines.
- Function or method: at most 50 lines, enforced by Clippy `too_many_lines`.
- `src/main.rs`: at most 40 lines.
- God-file names `application/service.rs`, `infrastructure/postgres.rs`, and
  `transport/grpc.rs` are forbidden.

## Dependency direction

`domain <- application <- infrastructure/transport <- bootstrap`

- Domain is pure business data and policy. It cannot import SQLx, Axum, Tonic,
  protobuf contracts, or outer layers.
- Application contains use cases and ports. It cannot import concrete database,
  crypto, HTTP, gRPC, or protobuf implementations.
- Infrastructure implements application ports for PostgreSQL, Argon2, Ed25519,
  token digests, and notification persistence.
- Transport maps HTTP/gRPC messages to application commands and domain values.
  It cannot execute SQL.
- `main.rs` only delegates to bootstrap composition.

Every new feature must add a focused module and pass `scripts/check.sh`.

## Clippy policy

`Cargo.toml` denies `clippy::all`, `clippy::pedantic`, and `clippy::nursery`, plus
selected production restrictions such as `unwrap_used`, `expect_used`, `panic`,
`todo`, `dbg_macro`, and direct stdout/stderr printing. `clippy.toml` sets the
function limit to 50 lines and argument limit to 5. The Python checker remains
responsible for file length and architectural dependency direction because
Clippy does not provide a source-file line-count lint.
