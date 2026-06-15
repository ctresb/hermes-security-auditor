# PostgreSQL Deep Cuts, Connection Pooling, RLS, and Migration Safety

Companion to the PostgreSQL section of `backend-audit`. These are the database issues that survive "we use sqlx, everything is parameterized" and bite in production. Targets the project-pinned PostgreSQL version.

## A. Connection-pool state bleed (high-value, frequently missed)

A pooled connection carries session-level state. If a request mutates session state and the connection returns to the pool without reset, the next unrelated request (possibly another tenant/user) inherits it.

Audit for any of these executed on a pooled connection without a guaranteed reset:
- `SET ROLE` / `RESET ROLE`, `SET SESSION AUTHORIZATION`.
- `SET search_path = ...` (per-tenant schema switching is the classic offender).
- `SET app.current_tenant = ...` / any custom GUC used by RLS policies (`current_setting('app.current_tenant')`).
- `SET TIME ZONE`, `SET statement_timeout` (per-query), `SET role`-based privilege scoping.
- Advisory locks (`pg_advisory_lock`) not released → leak/exhaustion; prefer `pg_advisory_xact_lock` (auto-released at txn end).
- A connection left mid-transaction or in `aborted` state returned to the pool.

Correct patterns:
- Use `SET LOCAL ...` inside a transaction (auto-reset at commit/rollback) for per-request GUCs, never bare `SET`.
- For RLS tenant context, set the GUC with `SET LOCAL` at the start of each transaction, or pass tenant as a bind param in every query.
- Prefer per-request DB role via `SET LOCAL ROLE` inside a txn, or distinct pools per privilege level.
- sqlx `after_connect`/`after_release` hooks or pool `test_before_acquire` can reset state, but the safest design avoids session-scoped mutation entirely.

Cross-tenant data leak from a leaked `search_path`/tenant GUC is CRITICAL.

## B. pgbouncer / transaction pooling vs prepared statements

A real operational footgun for Rust:
- sqlx (and tokio-postgres) use server-side **prepared statements** and a client-side statement cache by default.
- pgbouncer in **transaction** or **statement** pooling mode multiplexes many clients over few server connections; a prepared statement created on one server backend is not visible when the next query lands on a different backend → `prepared statement "sqlx_s_x" does not exist` errors, or worse, intermittent failures under load.
- Fixes to verify: pgbouncer `pool_mode=session` (loses multiplexing benefit), OR disable statement caching (sqlx `.statement_cache_capacity(0)` / `prepared_statements=false` on the connection), OR pgbouncer ≥1.21 with `max_prepared_statements` configured and a client that uses the protocol-level prepared-statement support correctly.
- Flag deployments that put pgbouncer in transaction mode in front of sqlx without addressing this - it manifests as flaky production auth/DB errors, not a clean failure.

## C. Row-Level Security (RLS) correctness

For multi-tenant tables:
- Is RLS actually `ENABLE`d AND `FORCE`d (owner bypasses RLS unless `FORCE ROW LEVEL SECURITY`)? The app's runtime role must not be the table owner / must not have `BYPASSRLS`.
- Do policies cover ALL of `SELECT`/`INSERT`/`UPDATE`/`DELETE` (a `USING` clause without a `WITH CHECK` lets a row be updated INTO another tenant)?
- Does the tenant predicate come from a trusted source (a `SET LOCAL` GUC set server-side from the authenticated principal), not a client-supplied value?
- Is RLS the only control, or is it defense-in-depth behind explicit `WHERE tenant_id = $1`? Prefer both. App-layer-only tenant filters are fragile; RLS-only is fragile if GUC handling is buggy (see §A).

## D. Privilege & function-level risks

- `SECURITY DEFINER` functions: do they `SET search_path = pg_catalog, ...` explicitly? A definer function without a pinned search_path is a privilege-escalation vector (caller-controlled search_path resolves objects to attacker schemas).
- `COPY ... TO/FROM PROGRAM` and `COPY ... FROM '/file'`: superuser/`pg_execute_server_program`/`pg_read_server_files` → RCE / file read. Runtime role must never have these.
- Runtime role privileges: should be DML-only (`SELECT/INSERT/UPDATE/DELETE/EXECUTE` on needed objects). Flag `DROP`/`ALTER`/`CREATE`, `SUPERUSER`, `BYPASSRLS`, broad `GRANT ALL`, ownership of tables it queries, or migration privileges held at runtime.
- Extensions: untrusted/`SECURITY DEFINER`-heavy extensions, `plpython`/`plperlu` (untrusted languages = RCE), `dblink`/`postgres_fdw` (SSRF-from-DB to internal hosts).
- `LISTEN/NOTIFY`: NOTIFY payloads built from user data and consumed by a worker that treats them as commands = injection across the notify channel.

## E. Triggers, constraints, and invariant bypass

- Denormalized counters/state maintained by triggers (follower counts, claim counts, `verified` flags): can the trigger be bypassed by a path that writes the base table directly, or by `DISABLE TRIGGER` during bulk load that is never re-enabled / counts never recomputed?
- CHECK constraints as the only validator: app inserts user-controlled values that violate a CHECK → surfaces as an error the code may not handle (e.g. a too-long display name from an OAuth profile failing a `length<=50` CHECK → unrecoverable login). The app should clamp/validate before the DB backstop.
- Missing `ON DELETE` behavior: FK columns without explicit `ON DELETE CASCADE/SET NULL/RESTRICT` (e.g. a `creator_id` with default `NO ACTION`) cause orphan rows or delete failures; audit FK actions table-by-table, especially before a data migration.
- Unique constraints as race protection: check-then-insert without a backing unique constraint is a TOCTOU; the constraint must exist and the code must handle the conflict (and handle the RIGHT constraint - see the identity-linking email-collision pattern).

## F. Migration safety

- **Never edit an already-applied migration.** sqlx `migrate!` records a checksum; editing a shipped file → checksum mismatch → boot failure (or, with some configs, silent divergence between environments). Pre-launch (no deployed DB) editing is acceptable; flag any edit to a migration that may have run anywhere.
- **Locking migrations = downtime DoS.** `ALTER TABLE ... ADD COLUMN ... DEFAULT <volatile>` (pre-PG11 rewrites; even on 18 some forms rewrite), adding a `NOT NULL` without a default on a big table, `ALTER TYPE`, creating an index without `CONCURRENTLY`, `ADD CONSTRAINT` validating immediately - all take `ACCESS EXCLUSIVE` and block the table. On large tables this is an availability incident. Prefer `ADD COLUMN` nullable → backfill in batches → set NOT NULL via `NOT VALID` + `VALIDATE CONSTRAINT`; `CREATE INDEX CONCURRENTLY` (note: can't run in a txn, conflicts with transactional migrators - flag the tension).
- **Destructive/irreversible**: `DROP COLUMN/TABLE`, `TRUNCATE`, data-loss type narrowing. Require a stated rollback and backup step.
- **Schema + data mixed**: large data backfills inside a schema migration hold locks and can time out; prefer separate, resumable data migrations.
- **Migration role separation**: migrations need DDL; runtime should not. `APP_DB_RUN_MIGRATIONS=true` at app boot means the runtime role has DDL → blast radius of an app compromise includes schema. Flag boot-time migration in production; recommend a separate migration job/role.
- **Determinism on PG18**: migrations using `gen_random_uuid()`/`uuidv7()`/version-specific functions must match the project's UUID policy and the pinned PG major. A `DEFAULT` calling a function that doesn't exist on the target server fails at apply time.

## G. Query DoS and plan stability (beyond the SKILL.md basics)

- `ILIKE '%term%'` / leading-wildcard / unanchored regex / `~*` on user input → seq scans; needs trigram (`pg_trgm` GIN) index or it's a CPU DoS.
- `to_tsquery(user_input)` raises on malformed input (DoS) and can build expensive queries; use `websearch_to_tsquery`/`plainto_tsquery`.
- JSONB containment/path queries on unindexed columns → full scans; `@>` needs a GIN index.
- `OFFSET` deep pagination → scans skipped rows; prefer keyset/cursor pagination (and UUIDv7/v8-time-ordered keys help, but v8-random does NOT give time ordering - verify pagination doesn't assume ordering it won't get).
- `fetch_all` with no LIMIT on a user-growable table → unbounded memory; require caps + streaming.
- Missing indexes on auth predicates (`token_hash` unique, `(provider, provider_user_id)` unique, `lower(email)`) - verify the hot auth lookups are all indexed.

## H. Verify dynamically, not just statically

Static review misses runtime-only bugs (constraint collisions, migration apply failures, RLS gaps). When feasible, the auditor should:
```bash
docker run -d --rm --name pg-audit -e POSTGRES_USER=app -e POSTGRES_PASSWORD=app -e POSTGRES_DB=app -p 55432:5432 postgres:<project-version>
# wait for pg_isready, then:
APP_DB_TEST_URL=postgres://app:app@localhost:55432/app cargo test -p <db-crate> -p <auth-crate> --test integration
# run migrations against it; confirm they apply cleanly and the gated integration suite is green.
docker stop pg-audit
```
This single step has surfaced real bugs (e.g. a unique-index collision in an account-linking path) that pure static review rated "fine".
