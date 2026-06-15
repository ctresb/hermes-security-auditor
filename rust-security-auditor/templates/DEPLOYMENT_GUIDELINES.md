# Deployment Guidelines

This file is a governance template for Rust backend audits. Replace placeholders with project-specific values before production use.

## Required Project Policy

- PostgreSQL version: pin the exact major version or managed database target used by production.
- Identifier policy: state whether the project uses UUIDv4, UUIDv7, UUIDv8, ULID, integer IDs, or another scheme.
- No weak secrets in any environment that can be deployed.
- No production default may be implicit. Every production secret/config value must be explicitly supplied by the deploy environment.
- Production must fail closed when required env vars are missing.

## Required Environment Variables

| Variable | Required | Example generation | Notes |
|---|---:|---|---|
| `DATABASE_URL` | yes | `printf 'postgres://USER:REDACTED@HOST:5432/DB?sslmode=verify-full
'` | Never commit. Use strong generated password. |
| `APP_SECRET_KEY` | yes | `openssl rand -base64 48` | Must decode to at least 32 random bytes. Rename to the project's real env var. |

Do not use examples like `password`, `secret`, `changeme`, `admin`, `postgres`, or `localhost` for deploy unless explicitly marked local-only and blocked from production.

## Secret Generation

```bash
openssl rand -base64 48
openssl rand -hex 32
```

## Deployment Steps

1. Build artifact/image.
2. Provision the project-pinned PostgreSQL version.
3. Create DB users/roles with least privilege.
4. Generate secrets using commands above.
5. Apply migrations using the migration role, not the runtime role.
6. Start service with explicit env vars.
7. Run health/readiness checks.
8. Verify auth, database connectivity, and critical routes.

## Rollback

1. Stop new traffic.
2. Roll back app artifact/image.
3. Roll back reversible migrations only if the migration explicitly supports rollback.
4. Restore from backup for destructive schema/data changes.
5. Re-run health/readiness checks.

## Verification Checklist

- [ ] All required env vars are explicitly set.
- [ ] No weak default secrets in Compose, `.env.example`, scripts, or docs.
- [ ] Production deploy fails closed when required env vars are missing.
- [ ] Project-pinned database version is enforced.
- [ ] Identifier policy is documented and enforced or documented as a finding.
- [ ] `DATABASE_URL` uses TLS for remote DB.
- [ ] Runtime DB role is least-privilege and cannot run DDL.
- [ ] Health/readiness checks pass.
- [ ] Rollback path is documented and tested.
