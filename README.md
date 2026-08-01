# auth-service

PostgreSQL-backed internal gRPC service for users, credentials, email verification,
email changes, sessions, Ed25519 access tokens, refresh rotation, lockout and audit.
HTTP is limited to health and metrics on port `8081`.

```bash
./scripts/check.sh
cargo run --locked
```

Runtime variables are documented in `.env.coolify.example`. Migrations run during
startup and use optimistic `version` checks for mutable profile/session resources.
