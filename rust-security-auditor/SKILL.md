---
name: rust-security-auditor
description: Use when auditing Rust backend code (Axum/Actix/Rocket/Tower) with PostgreSQL or similar relational stores; async runtimes, SQLx/Diesel/SeaORM, OAuth2/OIDC, sessions, multi-tenant/RLS, connection pooling, migrations, crypto/secrets, dependency supply chain, unsafe boundaries, and AI/LLM features. Produces an adversarial security/performance audit with ranked exploit chains, dynamic verification, and a detailed markdown report.
version: 1.0.0
author: Hermes Agent + contributors
license: MIT
metadata:
  hermes:
    tags: [rust, backend, security, audit, postgresql, ai-security, threat-modeling, performance]
    related_skills: [systematic-debugging, requesting-code-review, test-driven-development, codebase-inspection]
---

# Rust Security Auditor

## Overview

This skill audits Rust backend systems as an adversarial reviewer. It is optimized for Rust web APIs, PostgreSQL-backed services, async runtimes, dependency supply chain risk, unsafe boundaries, and AI/LLM integrations. The goal is not to run a generic checklist. The goal is to predict how a capable attacker would chain small mistakes into real compromise: data theft, auth bypass, privilege escalation, denial of service, persistence, cost abuse, prompt/tool hijacking, or destructive database actions.

Think in systems, not isolated bugs. A low-severity parser panic becomes critical if it is reachable pre-auth and restarts the only worker. A harmless dynamic `ORDER BY` becomes SQL injection when combined with unvalidated column names. A safe Rust endpoint becomes unsafe when a blocking Diesel connection is held across `.await` and starves Tokio. An LLM summary feature becomes data exfiltration when retrieved documents can inject tool calls.

The final output should be a detailed markdown report with ranked findings, exploitability reasoning, affected code paths, abuse chains, remediation, and verification steps. Prefer a new timestamped audit directory named `audit_DD-MM-AAAA-HH-MM/` at the backend root, with the main report at `audit_DD-MM-AAAA-HH-MM/RUST_BACKEND_SECURITY_AUDIT.md`, unless the user or repository asks for a different path.

## When to Use

Use this skill when asked to:

- Audit Rust backend code for vulnerabilities, reliability risks, or hacker-mindset abuse paths.
- Review PostgreSQL usage in Rust: SQLx, Diesel, tokio-postgres, deadpool-postgres, bb8, SeaORM, raw SQL, migrations, row-level security, pool sizing, transactions.
- Audit Axum, Actix Web, Rocket, Warp, Tower middleware, extractors, auth, sessions, CORS, cookies, uploads, websockets, background jobs, queues, or webhooks.
- Review Rust dependency supply chain and crate security using `cargo audit`, `cargo deny`, `cargo tree`, lockfile checks, and malicious/typosquat crate heuristics.
- Review AI/LLM features inside Rust services: prompt injection, RAG poisoning, excessive agency, unsafe output handling, memory poisoning, tool-call abuse.
- Produce a severity-ranked markdown report, not just quick comments.

Do not use for:

- Frontend-only reviews.
- Pure performance tuning with no security angle.
- Offensive exploitation against third-party systems. Keep all testing scoped to the user's code, local environment, or explicitly authorized targets.

## Core Audit Philosophy

1. **Assume attackers chain weaknesses.** Do not dismiss a finding because it is not exploitable alone. Ask what it unlocks.
2. **Follow trust boundaries.** User input includes HTTP bodies, headers, cookies, query strings, path params, JWT claims, database rows, cache values, webhook payloads, S3/object metadata, emails, markdown, LLM outputs, and admin-configured templates.
3. **Treat database content as attacker-controlled after first write.** Stored XSS has backend analogues: poisoned rows can drive dynamic SQL, LLM prompts, webhook dispatch, URL fetches, template rendering, authorization decisions, or background jobs.
4. **Rust memory safety is not application safety.** Rust reduces memory corruption, but does not prevent SQL injection, auth bugs, SSRF, DoS, logic flaws, unsafe misuse, dependency compromise, blocking runtime starvation, or prompt injection.
5. **Prefer proof over vibes.** Every finding should cite a code location, reachable flow, why existing guards fail, and how to verify the fix.
6. **Look for negative space.** Missing tests, missing timeouts, missing limits, missing transaction boundaries, missing `FOR UPDATE`, missing `SameSite`, missing pool limits, missing `#[serde(deny_unknown_fields)]`, missing authorization after object lookup.
7. **Assume AI-authored code hides laziness.** AI coding agents often silence warnings, leave dead code, duplicate utilities, invent docs, skip deployment rigor, stop after partial verification, and forget earlier constraints. Audit for those artifacts directly.
8. **Treat deployment as code.** Unsafe defaults in `.env.example`, Compose files, Dockerfiles, scripts, README snippets, or deployment docs are findings even if labeled "dev". Development credentials must be strong and explicit, not toy passwords.

## Project-Specific Policy Checks

Before treating any convention as mandatory, read the repository's own docs, config, migrations, and deployment files. Audit against the project's stated policy, not against one contributor's private defaults.

Common policy checks:

- **Identifier policy:** identify whether the project uses UUIDv4, UUIDv7, UUIDv8, ULID, Snowflake-style IDs, integer IDs, or another scheme. Flag mixed or undocumented schemes when they create authorization, enumeration, migration, or compatibility risk.
- **Database version policy:** identify the project's pinned PostgreSQL version or managed database target. Flag `postgres:latest`, unpinned database images, vague docs, and code that silently relies on a different version than deployment.
- **Environment security:** every environment, including local/dev/test, should avoid deployable weak secrets. Weak sample passwords such as `password`, `secret`, `changeme`, `admin`, `postgres`, or `123456` are findings unless clearly local-only and blocked from production.
- **Deployment determinism:** deployment docs should be exact enough for a new maintainer or automated agent to follow safely: explicit commands, rollback path, health checks, required env vars, and fail-closed behavior.
- **Operator model:** assume future human or automated operators may not remember chat context. Encode critical instructions in repository files, exact commands, checklists, and audit artifacts.

## Required First Pass

Before writing findings, establish the system map and create the audit workspace.

0. If the user asks to delete a previous audit first, do that before creating the new report, but keep it surgical:
   - Search for prior audit artifacts such as `audit_*`, `RUST_BACKEND_SECURITY_AUDIT.md`, or known legacy report paths.
   - Delete only the explicitly identified previous audit/report, not unrelated docs or user work.
   - Verify deletion with a real filesystem check and record exactly what was removed in the new report.
   - If multiple candidate audit directories exist and the user did not specify which one, prefer the latest obvious audit artifact only when safe; otherwise ask.
1. Create a backend-root directory named `audit_DD-MM-AAAA-HH-MM/` using the current local date/time, and write all audit artifacts there. The main report path is always `audit_DD-MM-AAAA-HH-MM/RUST_BACKEND_SECURITY_AUDIT.md`.
2. Identify workspace shape:
   - `Cargo.toml`, workspace members, feature flags, binaries.
   - Framework: Axum, Actix, Rocket, Warp, custom Hyper.
   - Database stack: SQLx, Diesel, tokio-postgres, SeaORM, migrations.
   - Auth stack: JWT, sessions, OAuth, API keys, cookies, password hashing.
   - Runtime stack: Tokio, async-std, background tasks, queues, cron jobs.
   - Serialization: Serde JSON, multipart, protobuf, GraphQL, templates.
   - External surfaces: webhooks, object storage, email, LLM APIs, payment APIs, browser extension APIs.
3. Build data-flow and trust-boundary notes:
   - Entrypoints.
   - Authenticated vs unauthenticated routes.
   - Admin-only routes.
   - Database writes and reads.
   - Background jobs consuming persisted data.
   - Places where untrusted data becomes SQL, URL, path, command, prompt, HTML, email, webhook, or log line.
4. Run lightweight mechanical checks when safe:
   - `cargo metadata --format-version 1`
   - `cargo tree -e features`
   - `cargo audit` if installed, otherwise note missing tool and use lockfile review.
   - `cargo deny check` if config/tool exists.
   - `cargo clippy --all-targets --all-features -- -D warnings` if project build is expected to work.
   - Existing tests, preferably focused first. Do not invent passing results.
5. Review repository markdown before writing findings:
   - Read backend-related `README.md`, `docs/**/*.md`, deployment docs, architecture docs, auth docs, database docs, runbooks, and `.env.example` comments.
   - Verify docs against code. Flag misconceptions, stale commands, invented env vars, wrong DB/UUID policy, wrong routes, unsafe examples, or missing warnings.
6. Check for `DEPLOYMENT_GUIDELINES.md` at backend root:
   - If missing, create it from this skill's `templates/DEPLOYMENT_GUIDELINES.md` and mark in the report that it was created as an audit artifact/requested governance file.
   - If present, audit it for determinism, secret generation commands, database version policy, identifier policy, env handling, rollback, health checks, and production fail-closed behavior.

### Dynamic verification (do not rely on static review alone)

Static-only review systematically misses runtime bugs: migrations that fail to apply, unique-constraint collisions, RLS gaps, pool state bleed, and conflict-handling that only covers the wrong constraint. When the project has a test suite and migrations, **stand up a throwaway PostgreSQL instance matching the project's pinned version and actually run them**:

- Set `PG_IMAGE` to the project-pinned PostgreSQL image, then run a throwaway `pg-audit` container, wait for `pg_isready`, point the project's test DB URL at it, run the gated integration suite and migrations, then `docker stop`.
- Confirm: migrations apply cleanly in order (and re-running on a dirty DB exposes test-isolation issues), the auth/identity flows behave, and no constraint path 500s. Reset the DB (`DROP DATABASE ... WITH (FORCE); CREATE DATABASE ...`) between full re-runs.
- This is how the real account-linking unique-email collision in the reference notes was found - pure static review rated it "fine". Record exactly what ran and its result; never imply tests passed that you did not run.

### Adversarial find -> refute pass

Do not ship a finding on first impression. For each candidate, run a deliberate refutation pass: read the actual code path end-to-end and try to prove it is NOT exploitable given the real guards (PKCE, client_secret, fixed redirect_uri, RLS, unique constraints, type bounds). Downgrade or drop what survives refutation; keep what doesn't, with the precondition that gates it stated explicitly. Separate "real and exploitable today" from "real but defense-in-depth" - label both honestly rather than inflating severity.

## Rust-Specific Vulnerability Classes

### 1. Unsafe Rust and Soundness Boundaries

Audit all `unsafe`, FFI, raw pointers, transmutes, manual `Send`/`Sync`, global state, `MaybeUninit`, custom allocators, and C bindings.

Red flags:

- `unsafe` blocks without a nearby `SAFETY:` comment explaining invariants.
- `std::mem::transmute`, `from_raw_parts`, `from_raw`, `set_len`, `assume_init`, `zeroed`, `uninitialized` patterns.
- Manual `unsafe impl Send` or `unsafe impl Sync` for types containing raw pointers, cells, handles, or FFI resources.
- FFI functions accepting borrowed Rust references across async or callback boundaries.
- C string conversion without NUL handling or lifetime control.
- Panic crossing FFI boundary.
- Safe wrapper around unsafe internals that does not enforce length, alignment, aliasing, lifetime, initialization, or thread-safety constraints.

Attacker mindset:

- Can user input influence buffer length, pointer offset, slice length, enum discriminant, deserialization type, FFI path, or callback timing?
- Can panic/unwind skip cleanup and leave shared state inconsistent?
- Can one safe public API call sequence violate unsafe invariants?

Severity guidance:

- Critical if memory corruption or arbitrary code execution is reachable remotely or through stored attacker data.
- High if safe API unsoundness can cause UAF, double-free, OOB read/write, cross-tenant leak, or crash.
- Medium if unsafe is isolated but lacks invariant proof and is hard to validate.

### 2. Panics, `unwrap`, `expect`, and Process-Kill DoS

Rust panics are often exploitable denial-of-service in backend code.

Red flags:

- `unwrap()`, `expect()`, `panic!`, indexing `[0]`, `todo!`, `unreachable!` in request paths, extractors, middleware, DB row mapping, JWT parsing, JSON parsing, multipart handling, background job consumers.
- `.parse().unwrap()` on user input.
- `serde_json::from_value(...).unwrap()` on external API responses or DB JSON.
- `rows[0]` after queries that can return zero rows.
- `HeaderValue::to_str().unwrap()` or timestamp/UUID parsing unwraps.

Attacker chains:

- Pre-auth panic plus systemd/Kubernetes restart loop equals cheap DoS.
- Panic inside transaction may roll back but leave external side effects already triggered.
- Panic in background worker can stop job processing and freeze billing, moderation, email, or cleanup.

Audit action:

- Classify every panic by reachability: pre-auth, post-auth, admin, internal, test-only.
- Demand typed errors and controlled HTTP responses for reachable panics.
- Add regression tests for malformed, missing, oversized, and weird-but-valid inputs.

### 3. Integer, Time, and Size Logic

Rust debug builds catch some overflow; release builds wrap unless using checked APIs or overflow-checks.

Red flags:

- Arithmetic on limits, offsets, pagination, prices, balances, quotas, TTLs, file sizes, vector capacities, retry delays, exponential backoff, token budgets.
- `as` casts between signed/unsigned or narrowing integer types.
- `usize` from user-controlled JSON length, path param, or DB value.
- Duration math from attacker input.
- `Vec::with_capacity(user_value)` or `String::repeat(user_value)`.

Attacker chains:

- `limit * page` overflow bypasses pagination bounds.
- Negative signed value cast to `usize` becomes huge allocation.
- TTL overflow makes tokens never expire or expire immediately.
- Price/counter overflow bypasses billing or rate limits.

Required remediation:

- Use `checked_*`, `saturating_*` only when saturation is semantically safe, `NonZero*`, bounded newtypes, and explicit maximums.
- Add property tests for boundary values: `0`, `1`, max allowed, max+1, `i64::MAX`, `usize::MAX`, negative, huge strings.

### 4. Async Runtime Starvation and Blocking Hazards

Rust async services fail when blocking work consumes runtime threads.

Red flags:

- `std::fs`, `std::thread::sleep`, blocking crypto, image/video processing, compression, synchronous HTTP clients, Diesel sync operations, `Command::output`, DNS blocking, large JSON parsing on async worker threads.
- Holding `Mutex`, `RwLock`, DB connection, transaction, semaphore permit, or request body stream across `.await` unnecessarily.
- `tokio::sync::Mutex` around high-contention global state.
- Clippy lints: `await_holding_lock`, `await_holding_refcell_ref`, `future_not_send`, `let_underscore_future`.
- Unbounded `tokio::spawn` per request, no join/timeout/backpressure.

Attacker chains:

- Send slow requests that make handlers hold pool connections across network calls, starving DB pool.
- Trigger CPU-heavy JSON/password/hash/compression path repeatedly, starving Tokio worker threads.
- Force many background tasks and exhaust memory because task queue is unbounded.

Required remediation:

- Move blocking work to `spawn_blocking` or dedicated worker queues with limits.
- Drop locks/connections before `.await` when possible.
- Add per-route concurrency limits, timeouts, request body limits, and backpressure.

### 5. Dead Code, Warning Suppression, and AI Cruft

AI-generated Rust often silences the compiler instead of removing bad code. Treat broad suppression as suspicious.

Red flags:

- `#![allow(dead_code)]`, `#[allow(dead_code)]`, `#![allow(unused)]`, `#[allow(unused)]`, `#[allow(unused_imports)]`, `#[allow(unused_variables)]`, or broad `#[allow(clippy::...)]` in production modules.
- `#[expect(...)]` used broadly, stale, or without a clear reason.
- Public visibility (`pub`, `pub(crate)`) used only to avoid dead-code warnings.
- Duplicate helpers, old code paths, unused feature modules, stale repository methods, unreachable routes, or config fields that are never consumed.
- `TODO`, `FIXME`, `temporary`, `legacy`, `compat`, `stub`, `placeholder`, or `not used yet` around auth, DB, deploy, or security code.
- Dead migrations/docs/env vars that describe behavior absent from code.

Audit action:

- Search for `allow(dead_code)`, `allow(unused`, `expect(unused`, `allow(clippy`, `dead_code`, `TODO`, `FIXME`, `stub`, `placeholder`, and `unused`.
- Classify each suppression: test-only, generated code, FFI/API boundary, migration compatibility, or unjustified.
- Require narrow scoping and comments for justified suppressions.
- Flag broad crate-level suppressions in production crates as Medium or High when they can hide security-critical unreachable/unfinished code.
- Prefer deleting dead code or making the intended call path real. The skill audits and reports; it does not implement the deletion unless separately asked.

### 6. Dependency and Supply Chain Risk

Rust projects depend heavily on crates. Malicious crates, yanked crates, unsound safe APIs, unmaintained crates, and feature confusion are recurring risks.

Required checks:

- `cargo audit` for RustSec advisories.
- `cargo deny check` for advisories, bans, duplicate versions, sources, licenses.
- `cargo tree -d` for duplicate versions and old vulnerable transitive crates.
- Inspect all `git =`, `path =`, unpinned branches, unusual registries, patched crates, and build scripts.
- Search dependency names for typosquats: `postgress`, `serd`, `oncecell`, `envlogger`, fake logging/tracing/time crates, near-matches to popular crates.
- Review crates with `build.rs`, proc macros, networked build steps, native libraries, OpenSSL bindings, libsqlite3 linkage, Wasmtime, archive/extraction crates, crypto crates.

Attacker chains:

- Malicious build script steals environment secrets in CI.
- Typosquat transitive dependency exfiltrates tokens during build.
- Unmaintained crypto/password crate keeps weak defaults.
- Native library linkage silently misses security backports.

Severity guidance:

- Critical if malicious crate or build-time secret exfil path exists.
- High if known vulnerable crate is reachable in production path.
- Medium if vulnerable crate present but not reachable or dev-only, still fix or justify.

## PostgreSQL and Rust Database Audit

### 1. SQL Injection Beyond Simple Values

Parameterized values are necessary but not sufficient. Values can be bound; identifiers, table names, column names, sort directions, operators, JSON paths, SQL fragments, and raw migrations cannot be bound the same way.

Red flags:

- `format!`, `push_str`, `+`, `join`, `write!` used to build SQL.
- SQLx `query()` with dynamic strings instead of `query!()` or query builder with bind parameters.
- Diesel `sql_query`, `sql`, `into_boxed` with raw fragments, dynamic `order_by` implemented by string.
- Dynamic `ORDER BY`, `LIMIT`, `OFFSET`, `WHERE`, `ILIKE`, `IN (...)`, JSONB path, full-text query, `COPY`, schema/table/column name.
- Raw SQL inside migrations or admin endpoints accepting input.
- Stored procedures using dynamic SQL.

Attacker chains:

- Dynamic `ORDER BY {user}` lets attacker append expressions, timing probes, or subqueries.
- Dynamic JSON path or full-text query enables expensive expressions causing DB DoS.
- Multi-tenant `schema` or table name from tenant slug enables cross-tenant reads if not allowlisted.

Required remediation:

- Bind all values.
- Allowlist identifiers using enums, not regex-only validation.
- Map sort fields/directions to static SQL fragments.
- Prefer SQLx macros for static queries and compile-time checking.
- For dynamic query builders, verify every user-controlled value becomes a bind parameter.

### 2. Authorization Coupled to Database Access

Most backend breaches are authorization bugs, not memory bugs.

Red flags:

- Fetch object by ID, then check owner later or inconsistently.
- Update/delete by object ID without tenant/user predicate in SQL.
- Admin flag or role trusted from request body or unverified JWT claim.
- API returns full row/model and relies on frontend to hide fields.
- Missing row-level security for multi-tenant tables where appropriate.
- `WHERE id = $1` instead of `WHERE id = $1 AND tenant_id = $2`.
- Soft-deleted records not filtered everywhere.

Attacker chains:

- IDOR: enumerate UUIDs from logs, URLs, websocket events, or public profile references.
- Mass assignment changes `role`, `owner_id`, `tenant_id`, `is_verified`, `balance`, `plan`.
- Race between ownership check and update changes ownership or target row.

Required remediation:

- Enforce object-level authorization inside the same SQL statement that reads/writes the object.
- Use scoped repository methods that require authenticated principal/tenant.
- Add negative tests: user A cannot read/update/delete user B object; regular user cannot set admin fields.

### 3. Transactions, Races, and Invariants

Rust type safety does not protect database invariants.

Red flags:

- Check-then-insert/update without unique constraints or transaction isolation.
- Balance, quota, inventory, invite, subscription, vote, or rate-limit changes outside transactions.
- Multiple DB writes plus external API call with no idempotency key/outbox pattern.
- `SELECT` then `UPDATE` without `FOR UPDATE` or atomic `UPDATE ... WHERE ... RETURNING`.
- Webhook handlers not idempotent.
- Background workers can process same job twice.

Attacker chains:

- Parallel requests bypass quotas or double-spend credits.
- Replay webhooks create duplicate grants.
- Crash after external side effect but before DB commit causes inconsistent state.

Required remediation:

- Prefer atomic SQL updates with predicates and `RETURNING`.
- Add unique constraints and database-level checks.
- Use transactions with appropriate isolation or locks.
- Add idempotency keys for payments/webhooks/actions.
- Use outbox pattern for external side effects.

### 4. Pool Exhaustion and Query DoS

Database DoS often comes from valid-looking requests.

Red flags:

- Unbounded `fetch_all`, no pagination cap, no request timeout, no statement timeout.
- Pool max size too high for Postgres `max_connections` or too low for route concurrency.
- Holding transactions/connections across HTTP calls, LLM calls, sleeps, file uploads, streaming responses.
- N+1 queries in list endpoints.
- Regex, `ILIKE '%term%'`, full-table scans, JSONB scans, or unindexed filters reachable by user.
- No `EXPLAIN` review for high-traffic queries.

Attacker chains:

- Use many concurrent slow filters to occupy every pool connection.
- Query huge exports repeatedly and exhaust memory through `fetch_all`.
- Trigger worst-case search term and pin CPU in Postgres.

Required remediation:

- Enforce max `limit`, cursor pagination, streaming with backpressure, statement timeouts.
- Add indexes for auth predicates and common filters.
- Use `EXPLAIN (ANALYZE, BUFFERS)` for suspicious queries on realistic data.
- Configure pool timeout, idle timeout, max lifetime, and health checks.

### 5. Secrets, TLS, Database Privileges, and Deployment Defaults

Red flags:

- `NoTls` to remote Postgres or managed DB over network.
- Superuser database credentials in app config.
- Same DB role for migrations and runtime.
- Secrets in `.env`, logs, Dockerfiles, CI output, panic traces.
- SQLx compile-time `DATABASE_URL` requiring production credentials.
- Broad grants: runtime can `DROP`, `ALTER`, read all schemas, bypass RLS.
- Weak defaults anywhere, including dev: `password`, `secret`, `changeme`, `admin`, `postgres`, `123456`, short tokens, copied sample OAuth secrets.
- Production Compose/Kubernetes/systemd configs that silently default secrets, DB names, ports, origins, or TLS mode.
- Missing or vague `DEPLOYMENT_GUIDELINES.md`.
- Deployment docs that require human judgment instead of exact commands for automated operators.

Required remediation:

- Runtime DB role has least privilege: only required `SELECT/INSERT/UPDATE/DELETE/EXECUTE`.
- Separate migration role.
- TLS for remote DB.
- Secret redaction in errors/logs.
- Offline SQLx metadata or non-prod build DB for compile-time checking.
- Strong generated secrets in every environment, including development.
- Production must fail closed when required env vars are absent.
- `DEPLOYMENT_GUIDELINES.md` must provide deterministic steps, exact secret-generation commands, env file permissions, migration/rollback commands, health checks, and verification.

### 6. Database Version and Identifier Policy Review

Do not force a private identifier or database-version preference onto every project. Discover and audit the policy the repository claims to use.

Audit requirements:

- Search manifests, migrations, SQL, docs, Docker Compose, CI, and deployment files for database image/version pins.
- Flag `postgres:latest`, unpinned major versions, docs that merely say "Postgres" without a version, or code/migrations that rely on behavior from a different version than deployment.
- Search for identifier generation and storage policy: `Uuid::new_v4`, `Uuid::now_v7`, `uuidv7()`, `uuidv8`, `gen_random_uuid()`, ULID/Snowflake generators, random strings, serial/bigserial IDs, integer IDs, or mixed schemes.
- Flag undocumented, mixed, or migration-incompatible identifier schemes. Do not require UUIDv8 unless the project itself says UUIDv8 is policy.
- Verify docs and `.env.example` state the database version and identifier policy consistently.

### 7. Connection Pooling, RLS, Migrations, and PG Deep Cuts

Issues that survive "we use sqlx and everything is parameterized". Full playbook in `references/postgres-deep-and-pooling-audit.md`. High-signal red flags:

- **Pool state bleed**: `SET ROLE`/`SET search_path`/`SET app.current_tenant`/custom GUCs or unreleased `pg_advisory_lock` on a pooled connection without guaranteed reset -> state (and tenant scope) leaks to the next request on that connection. Use `SET LOCAL` inside a transaction, or bind tenant per-query. Cross-tenant leak from a leaked tenant GUC is CRITICAL.
- **pgbouncer transaction-pooling vs sqlx prepared statements**: server-side prepared statements + transaction pooling = intermittent `prepared statement does not exist` failures. Verify `pool_mode=session`, disabled statement cache, or a pgbouncer/client combo that handles it.
- **RLS**: enabled AND forced (`FORCE ROW LEVEL SECURITY`; runtime role not table owner, no `BYPASSRLS`); policies cover all of SELECT/INSERT/UPDATE/DELETE (a `USING` without `WITH CHECK` lets a row be updated INTO another tenant); tenant predicate from a server-set GUC, not client input; ideally RLS + explicit `WHERE tenant_id` defense-in-depth.
- **Privilege escalation in DB**: `SECURITY DEFINER` functions without a pinned `search_path`; `COPY ... PROGRAM`/`pg_read_server_files` (RCE/file read); runtime role with DDL/`SUPERUSER`/`BYPASSRLS`/ownership; untrusted PLs (`plpythonu`/`plperlu`), `dblink`/`postgres_fdw` (SSRF-from-DB).
- **Migrations**: never edit an already-applied migration (sqlx checksum drift -> boot failure/divergence); `ACCESS EXCLUSIVE` locking migrations (`ADD COLUMN ... DEFAULT volatile`, `NOT NULL` without default on big tables, `CREATE INDEX` without `CONCURRENTLY`, immediate `ADD CONSTRAINT`) = downtime DoS; destructive/irreversible migrations without rollback; boot-time migration in prod means runtime role holds DDL.
- **Invariant bypass**: trigger-maintained counters/flags bypassable by direct base-table writes or disabled-during-load-and-never-recomputed; CHECK constraints as the only validator (app must clamp before the DB backstop); FK columns missing explicit `ON DELETE`; check-then-insert without a backing unique constraint.
- **Query DoS**: leading-wildcard `ILIKE`/unanchored regex without trigram index; `to_tsquery(user_input)` (raises/expensive - use `websearch_to_tsquery`); unindexed JSONB `@>`; deep `OFFSET` pagination; `fetch_all` with no cap. Confirm hot auth lookups (`token_hash`, `(provider, provider_user_id)`, `lower(email)`) are all indexed.

## Web/API Security in Rust Backends

### Auth, OAuth/OIDC, Sessions, and Federated Identity

This is where Rust services most often get the framework right and the *protocol* wrong. For the deep playbook (PKCE/state/nonce, id_token validation, mix-up, identity-linking takeover, ban gate, exploit prompts) see `references/oauth-oidc-session-identity-audit.md`. High-signal red flags:

OAuth 2.0 / OIDC (RFC 6749/6750/7636/9700/9207, OIDC Core, RFC 8725):
- Missing/static/predictable `state`, or `state` not bound to the browser and compared on callback -> login-CSRF.
- `nonce` never generated/validated (distinct from `state`; it is the ID-token replay binding).
- PKCE absent for public clients, or `plain` instead of `S256`.
- **ID token not validated / audience not bound**: profile read from the **userinfo** endpoint with no `aud == client_id` (+`iss`,`exp`,`azp`,`nonce`) check. Drops audience binding (confused-deputy). Validate the id_token from the token-endpoint response (OIDC §3.1.3.7 permits skipping the signature for tokens received directly over TLS - never for caller-supplied JWTs). Take `sub`/`email`/`email_verified` from the validated token, not an unauthenticated GET.
- redirect_uri not exact-match allowlisted; open redirect on the final app-bounce hop; auth-code not single-use/bound to client+PKCE.
- Mix-up: multiple providers without `iss` response-param (RFC 9207) or distinct redirect_uris.

JWT-as-session (if used): reject `alg:none`; pin alg/key type (RS256->HS256 public-key-as-HMAC confusion); allowlist `kid` (path/SQLi injection); ignore embedded `jwk`/`jku`/`x5u`; remember JWTs can't be revoked without a denylist (flag "logout/ban doesn't invalidate live JWTs").

Sessions (opaque): ≥256-bit OS-CSPRNG token, only its hash stored; expiry/revocation evaluated in SQL against `now()`; rotation at privilege boundaries; idle + absolute TTL (flag 30-day absolute with no rotation); `revoke_all_for_user`/"log out everywhere" actually wired to ban, not dead code; bearer not delivered in URL query/history (fragment-then-strip, or one-time exchange-code POSTed back).

**Ban/disable is an auth boundary, not a feature**: `verify()` must reject banned/disabled/suspended accounts on **every request**, not just at login - else a banned (or migrated-banned) user re-runs OAuth for a fresh session.

Federated identity / account linking (takeover surface):
- Auto-link a second provider by email only when `email_verified` is true AND from a per-provider trust allowlist (default-deny new providers); never link/persist an unverified email.
- `email_verified` must be authoritative (validated id_token, not userinfo).
- Email canonicalization: `lower()`/`citext` baseline; Gmail dot/+tag and IDN/Unicode homoglyphs can split/merge accounts - flag inconsistencies, esp. vs a predecessor system being migrated.
- Unique-email-index collision when auto-link is *declined* but the email exists -> create the account WITHOUT claiming the email; verify conflict-recovery covers the email constraint, not just username.
- Bootstrap/owner promotion check-then-set TOCTOU; provider `sub` preserved across a migration for seamless re-login.

Audit log: absence of an append-only auth-event trail (login/link/issue/revoke/owner-grant/blocked) is itself a finding for products that ban users or link accounts.

Classic basics still apply: password hashing Argon2id/bcrypt/scrypt with per-password salt and constant-time `verify` (no SHA/MD5/plain - and confirm an OAuth-only service has no dead password path); cookie `HttpOnly`/`Secure`/`SameSite`/scope; CSRF for cookie-auth state-changing routes; API keys hashed-at-rest, prefix-display, scoped, revocable; login/register/reset enumeration, one-time/expiring tokens, brute force, reset host-header poisoning.

### Input, Serialization, and Mass Assignment

Red flags:

- Request DTO reused as database model.
- `#[serde(flatten)]` or broad `serde_json::Value` accepted then merged into internal state.
- Missing `#[serde(deny_unknown_fields)]` on security-sensitive DTOs.
- Default values that grant access or skip checks.
- File upload names/paths trusted.
- Multipart/body size not limited.

### SSRF, URL Fetching, and Webhooks

Red flags:

- User-supplied URL fetched by backend.
- Webhook callback URL stored and later called by worker.
- Image/avatar/import URL fetcher.
- LLM/browser/scraper feature that fetches arbitrary URLs.
- No DNS/IP allow/deny controls, redirects followed blindly, no metadata IP blocking, no timeout/size cap.

Attacker chains:

- SSRF to cloud metadata endpoint, internal admin service, local Postgres/Redis, Kubernetes API.
- DNS rebinding bypasses initial validation.
- Redirect moves from allowed domain to private IP.

Required remediation:

- Allowlist schemes/hosts when possible.
- Resolve and block private/link-local/loopback/multicast ranges before connect and after redirects.
- Disable redirects or revalidate each hop.
- Set low connect/read timeouts and max bytes.

### Path, File, Archive, and Command Risk

Red flags:

- `PathBuf::push(user_input)`, `join` with absolute paths, `..` traversal, symlinks.
- Archive extraction without zip-slip/tar path validation.
- Filename used in shell command, image tools, ffmpeg, compression utilities.
- `Command` built through `sh -c` or untrusted args.
- Temporary files with predictable names or wrong permissions.

Required remediation:

- Canonicalize under fixed base directory and verify prefix after resolution.
- Reject absolute paths, parent components, NUL, weird Unicode if relevant.
- Pass command args as argv, never shell-concatenate.
- Use tempfile APIs.

### Logging and Observability

Red flags:

- Logging auth tokens, cookies, passwords, API keys, PII, database URLs, LLM prompts with secrets.
- Log injection via newlines/control chars in user-controlled fields.
- Debug traces in production HTTP responses.
- Error responses expose SQL, stack traces, internal IDs.

Required remediation:

- Structured logs with redaction.
- Safe public error type separate from internal error.
- Correlation IDs without leaking sensitive object IDs.

### Tower Middleware, CORS, and Security Headers

Layer ordering and scope are security-relevant. Deep playbook in `references/web-crypto-hardening-rust.md`.

- Middleware scope: `Router::layer` (whole router) vs `route_layer` (matched routes only - does NOT run for 404s). Verify auth/rate-limit/body-limit actually cover intended routes. Ordering: rate-limit and body-limit must sit OUTSIDE expensive auth/DB/buffering work.
- Missing `DefaultBodyLimit` on upload/`Bytes`/`Multipart` routes; missing `tower_http::catch_panic` (a reachable panic kills the connection/worker instead of returning 500); missing `TimeoutLayer`/`ConcurrencyLimitLayer`/`LoadShed` for expensive flows.
- `TraceLayer` logging `Authorization`/`Cookie`/secret-bearing query strings without redaction.
- **CORS traps**: reflecting `Origin` with `Allow-Credentials: true` (cross-site data theft); wildcard-with-credentials; allowlist via `starts_with`/`contains`/regex (`app.example.com.evil.com` bypass) instead of exact-match; `null` origin accepted; missing `Vary: Origin`. Flag "no explicit restrictive CORS policy" as a regression risk even when header-bearer auth makes it non-exploitable today.
- **Missing security headers** on prod surfaces: HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options`/CSP `frame-ancestors`, `Referrer-Policy`, `Cache-Control: no-store` on authed/sensitive responses.

### Inbound Webhooks and Signature Verification

- Verify the HMAC signature over the **raw request body bytes** before/without JSON re-serialization (Axum/Actix bug: extract `Json<T>` then re-serialize -> signature breaks or is skipped; capture `Bytes` first, verify, then parse).
- Constant-time signature compare (`subtle`/SDK), never `==` on the signature string.
- Replay window: verify provider timestamp, reject old requests, store processed event IDs for idempotency. Per-source rotated secret; reject unsigned/wrong-version.

### Cryptography, Secrets, and Constant-Time

Deep playbook in `references/web-crypto-hardening-rust.md`. Red flags:

- `==` on MACs/signatures/tokens/hashes (timing oracle) instead of `subtle::ConstantTimeEq` or the MAC's `verify_slice`.
- **Key length measured as characters, not entropy** (a 32-char passphrase is not 256 bits; require base64/hex of ≥32 random bytes and validate decoded length).
- Single signing key, no `kid`, no dual-key verify window -> rotation breaks in-flight tokens and is avoided.
- AEAD nonce reuse (`aes-gcm`); secrets from non-CSPRNG (`thread_rng`/seeded) instead of `getrandom`/`OsRng`; secrets in `Debug`/`Display`/panic messages (verify redacted impls); no `zeroize` for key material; native-tls/OpenSSL instead of rustls; remote DB without `sslmode=verify-full`.

### Deserialization and Resource-Allocation Attacks

- serde recursion/stack overflow on deeply nested input (verify the `serde_json` 128 default isn't bypassed by custom deserializers / other formats; cap size+nesting at the edge).
- Length-prefix allocation bombs in `bincode`/`postcard`/CBOR/MessagePack (`Vec::with_capacity(huge)` before reading) - use the format's size limit; never deserialize untrusted bytes without a byte cap.
- Missing `#[serde(deny_unknown_fields)]` on security DTOs; `flatten`/untagged-enum/`serde_json::Value` merged into internal state (mass-assignment of `role`/`tenant_id`/`is_admin`/`balance`); DTO reused as DB model.
- `Vec::with_capacity(user_n)`/`String::repeat(user_n)`/pre-size from a header; decompression/image/archive bombs (cap decompressed size + source pixels; decode in `spawn_blocking` + semaphore; zip/tar slip).

### Data Lifecycle, Audit Logging, and Compliance

- No append-only security audit trail (auth events, admin/destructive actions) -> incidents are unreconstructable. Absence is a finding for products that ban users, link accounts, or handle money.
- No account deletion / data export / right-to-erasure path; no unlink-provider (must keep ≥1 login method); no session-list/self-revoke UI; destructive `DELETE /account` with no re-auth/confirmation/audit event.
- No reaper for expired/revoked sessions, exchange codes, or stale tokens (unbounded growth + larger leak window). PII retention/minimization not addressed.

### Rate Limiting at Scale and Denial-of-Wallet

- In-memory per-instance limiter bypassed by horizontal scaling (N replicas -> N× limit) and lost on restart; for real limits use a shared store (Redis) or edge enforcement - note the limitation explicitly when only in-memory exists. Key on trusted client identity (socket peer, or `X-Forwarded-For` only behind a configured trusted proxy); bound/TTL-evict the key map.
- Stricter budgets on expensive/abusable endpoints (login, OAuth callback, token exchange, reset, search, export, email/SMS send). Any user-triggerable costly external action (email/SMS/push/S3/CDN/embeddings) is a cost-abuse vector needing per-user budgets and confirmation for high-cost/irreversible actions.

## AI/LLM Feature Audit for Rust Backends

If the backend touches AI, treat the LLM as an untrusted, probabilistic component. Prompt text is not an access-control mechanism.

### Common AI Vulnerability Classes

- Direct prompt injection: user text overrides developer intent.
- Indirect prompt injection: fetched web pages, emails, tickets, docs, PDFs, DB rows, or markdown contain hidden instructions.
- RAG/vector-store poisoning: malicious content persists and later hijacks unrelated users.
- Tool hijacking/excessive agency: model can call APIs, database actions, email, filesystem, or webhooks beyond user authorization.
- Sensitive information disclosure: model sees secrets, internal prompts, private documents, or cross-tenant data.
- Unsafe output handling: LLM output becomes SQL, shell, HTML, markdown, code, JSON command, policy decision, or URL without validation.
- Memory poisoning: attacker writes long-term memory that changes future behavior.
- Cost/resource abuse: attacker causes huge context, repeated tool loops, expensive model calls, or embeddings floods.

### AI Agent Failure Modes to Audit in Repositories

When code or docs may be AI-authored, also audit for process failures. Use `references/ai-agent-audit-failure-patterns.md` as supporting context.

High-risk AI artifacts:

- Context loss: duplicated functions, stale alternative implementations, contradictory docs, forgotten constraints, wrong route/env names.
- Laziness: broad `allow(dead_code)`/`allow(unused)`/`allow(clippy::...)`, TODOs around security, placeholder code, partial tests, fake examples.
- Hallucinated completion: report/README claims a check, migration, endpoint, or secret rotation exists when the code says otherwise.
- Premature termination: final docs say "done" but no command logs, no negative tests, no deploy verification, or no regression path.
- Scope drift: extra features, permissive defaults, weak dev envs, convenience shortcuts, or broad abstractions not requested.
- Long-context loss: documented project invariants missing in new files. Verify identifier policy, database version policy, strong envs, deterministic deployment docs, and timestamped audit output.

AI-operator stance:

- Assume future AI coding agents may operate this repository later.
- Do not rely on model memory, vibes, or an operator noticing ambiguity.
- Encode critical instructions in repository files, exact commands, checklists, and audit artifacts.
- Make findings and deployment steps impossible to misread: exact paths, exact env names, exact commands, exact pass/fail criteria.

### Rust Backend Red Flags

- LLM prompt built using `format!` with raw user input, DB rows, or fetched pages and no explicit data boundaries.
- LLM output parsed as trusted JSON and executed as an action.
- Tool/function calls authorized by model intent instead of server-side policy.
- RAG retrieval ignores tenant, ACL, freshness, source trust, or document owner.
- Embeddings/vector rows shared across tenants or user scopes.
- Prompt/system messages logged with secrets.
- Agent can call internal endpoints, SQL, shell, email, payment, or admin APIs.
- Model decides whether user is allowed to do something.
- No per-user/model/tool budget, loop limit, timeout, or human confirmation for destructive actions.

Required remediation:

- Treat all model inputs and outputs as untrusted data.
- Enforce authorization in deterministic Rust code before every tool/API/database action.
- Use schemas, strict parsers, allowlisted enum actions, and reject unknown fields.
- Keep tools least-privilege and scoped to the authenticated user.
- Add provenance labels to retrieved content and never let retrieved text become instructions.
- Use separate phases: retrieval -> sanitization/summarization -> decision -> deterministic validation -> action.
- Require confirmation for destructive, external, or high-cost actions.
- Log tool calls safely for audit, not raw secret prompts.

## Severity Ranking Model

Rank each finding with both severity and confidence.

### Severity

- **Critical**: Remote unauthenticated or low-privileged path to data breach, auth bypass, cross-tenant access, arbitrary code execution, database destruction, secret exfiltration, malicious dependency execution, or durable AI memory/tool compromise.
- **High**: Authenticated but broadly reachable serious impact; reliable DoS against core service; privilege escalation; SQL injection limited by DB role; SSRF to sensitive internal service; payment/quota race; unsafe Rust memory bug with realistic reachability.
- **Medium**: Requires specific role/state/timing or has bounded impact; important hardening gap; dependency advisory not clearly reachable; missing rate limits on costly operations; panic reachable post-auth.
- **Low**: Defense-in-depth issue, weak configuration, unclear reachability, limited leakage, code smell that may become dangerous as features grow.
- **Informational**: No direct vulnerability, but architecture note, missing documentation, or recommended monitoring/testing.

### Confidence

- **High**: Code path and exploitability are clear; tool/test confirms; no major assumptions.
- **Medium**: Strong evidence but needs runtime config/data volume/role confirmation.
- **Low**: Plausible risk pattern; needs deeper verification.

### Exploitability Questions

For each issue ask:

1. Who can reach it: unauthenticated, authenticated, tenant member, admin, external webhook, malicious dependency, stored attacker data?
2. What exact input controls the dangerous value?
3. What guard exists and why does it fail or remain insufficient?
4. What does the attacker gain immediately?
5. What second step becomes possible?
6. What blast radius exists: single user, tenant, all tenants, infrastructure, CI/build secrets?
7. What logs/alerts would or would not detect it?

## Required Report Format

The final report must be English markdown and include these sections.

```markdown
# Rust Backend Security Audit Report

Output path: `audit_DD-MM-AAAA-HH-MM/RUST_BACKEND_SECURITY_AUDIT.md`

## Executive Summary

- Overall risk: Critical/High/Medium/Low
- Scope reviewed: paths, crates, routes, database surfaces
- Most dangerous chain: short narrative
- Top remediation priorities:
  1. ...
  2. ...
  3. ...

## Methodology

- Tools/commands actually run and their results
- Manual review strategy
- Threat model assumptions
- Constraints or files not reviewed

## Attack Surface Map

### Entrypoints
| Surface | Auth | Trust Boundary | Notes |
|---|---:|---|---|

### Data Stores
| Store/Table | Sensitive Data | Tenant Boundary | Notes |
|---|---|---|---|

### External Integrations
| Integration | Direction | Risk |
|---|---|---|

## Findings

### [CRITICAL/HIGH/MEDIUM/LOW/INFO] Finding Title

**Severity:** High  
**Confidence:** High  
**Affected code:** `path/file.rs:line-line`  
**Category:** SQL Injection / AuthZ / DoS / Unsafe Rust / AI Security / Supply Chain / etc.

#### What happens
Explain the bug precisely.

#### Why it is dangerous
Explain impact and blast radius.

#### Attacker chain
1. Attacker controls ...
2. Backend trusts ...
3. This unlocks ...
4. Final impact ...

#### Evidence
```rust
// relevant snippet
```

#### Remediation
Concrete fix, preferably with Rust/SQL examples.

#### Verification
- Test to add
- Command to run
- Manual check

## Positive Security Notes

- Existing controls that reduce risk.

## Repository Documentation Review

- Markdown files reviewed
- Misconceptions, stale docs, unsafe examples, invented commands/env vars
- Required edits or follow-up recommendations

## Deployment Guidelines Review

- Whether `DEPLOYMENT_GUIDELINES.md` existed or was created
- Dev/prod env safety
- Secret-generation commands
- database version and identifier policy enforcement
- Production fail-closed behavior
- Rollback and verification steps

## AI-Agent Artifact Review

- Dead code and warning suppressions
- Context-loss/stale-code artifacts
- Hallucinated docs or impossible commands
- Premature completion / missing verification

## Dependency and Supply Chain Review

- RustSec/cargo-audit results
- cargo-deny/cargo tree notes
- Risky crates/features/build scripts

## Authentication, OAuth/OIDC & Identity Review

- Flow integrity: PKCE/state/nonce, redirect_uri allowlist, mix-up
- ID-token validation & audience binding (userinfo trust gap)
- JWT BCP if self-issued; session lifecycle/rotation/revocation
- Ban/disable gate on every request
- Federated identity linking & email canonicalization takeover surface
- Auth-event audit trail presence

## Database Review

- Query safety (values bound; identifiers allowlisted)
- Authorization predicates at the query level
- Transaction/race/idempotency safety
- RLS correctness; connection-pool state bleed; pgbouncer/prepared-statements
- Migration safety (checksum drift, locking, role separation)
- Pool/timeouts/indexes; query-DoS
- Least privilege/TLS/secrets

## Cryptography & Secrets Review

- Constant-time comparisons; key entropy vs length; key rotation
- CSPRNG usage; AEAD nonce handling; secret hygiene (`zeroize`, redacted `Debug`)
- TLS posture (rustls; DB `verify-full`)

## Web, Middleware & CORS Review

- Tower layer scope/ordering; body limits; panic-catch; timeouts
- CORS credentialed-reflection / allowlist-bypass; security headers; CSRF
- Inbound webhook signature verification (raw body, constant-time, replay)
- Deserialization/resource-allocation limits; rate-limiting at scale

## Data Lifecycle & Compliance Review

- Account deletion / export / erasure; provider unlink; session self-revoke
- Expired-token/session/exchange-code reaper; PII retention

## AI/LLM Review

- Prompt injection/RAG/tool/memory risks if applicable
- Deterministic server-side controls

## Performance-Driven Security Risks

- Pool exhaustion
- CPU/memory bombs
- N+1 queries
- Blocking async paths

## Remediation Roadmap

### Fix Now
- Critical/high items with direct patches.

### Fix Next
- Medium issues and hardening.

### Monitor
- Metrics, alerts, logs, abuse detection.

## Appendix

- Commands run
- Notable files reviewed
- Open questions
```

## Command Playbook

Use tools only when appropriate for the repository. Do not claim results without running them.

```bash
# Audit workspace
AUDIT_DIR="audit_$(date +%d-%m-%Y-%H-%M)"
mkdir -p "$AUDIT_DIR"
REPORT="$AUDIT_DIR/RUST_BACKEND_SECURITY_AUDIT.md"

# Workspace and dependencies
cargo metadata --format-version 1
cargo tree -e features
cargo tree -d
cargo audit
cargo deny check
cargo vet                 # if configured: third-party crate review state
# cargo auditable build   # embed an SBOM in the binary for later scanning

# Build and tests
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features

# Dynamic verification: apply migrations + run gated integration against a throwaway project-matching Postgres
PG_IMAGE="${PG_IMAGE:?set project-pinned Postgres image, e.g. postgres:17}"
docker run -d --rm --name pg-audit -e POSTGRES_USER=app -e POSTGRES_PASSWORD=app \
  -e POSTGRES_DB=app -p 55432:5432 "$PG_IMAGE"
# wait until ready: docker exec pg-audit pg_isready -U app
# point the project's test DB URL at it (name varies, e.g. TEST_DATABASE_URL):
TEST_DATABASE_URL=postgres://app:app@localhost:55432/app cargo test --all --all-features
# reset between full re-runs so test-isolation issues surface honestly:
docker exec pg-audit psql -U app -d postgres -c 'DROP DATABASE app WITH (FORCE); CREATE DATABASE app;'
docker stop pg-audit

# Search patterns (use proper file search tools when available)
# unsafe, unwrap, expect, panic, sql_query, format SQL, spawn, locks, NoTls, Command, URL fetchers

# PostgreSQL query review when a DB is available
EXPLAIN (ANALYZE, BUFFERS) <query>;
```

Prefer Hermes `search_files` over shell grep/find, `read_file` over cat/head, and `patch` over sed/awk when using Hermes tools.

## Captured Reference Notes

- See `references/oauth-oidc-session-identity-audit.md` for the deep auth playbook: PKCE/state/nonce, ID-token validation & the audience-binding/confused-deputy trap, mix-up, JWT BCP, opaque-session lifecycle, the ban gate, and federated-identity/account-linking takeover patterns.
- See `references/postgres-deep-and-pooling-audit.md` for connection-pool state bleed, pgbouncer-vs-prepared-statements, RLS correctness, `SECURITY DEFINER`/`COPY PROGRAM` privilege risks, migration safety (checksum drift, locking, role separation), and query-DoS deep cuts.
- See `references/web-crypto-hardening-rust.md` for Tower middleware ordering, CORS credentialed-reflection traps, security headers, inbound-webhook signature verification, constant-time crypto / key-entropy / rotation, and deserialization/resource-allocation attacks.
- See `references/rust-backend-audit-patterns.md` for recurring high-value chains from real Rust/Axum/PostgreSQL audits: spoofable proxy headers plus unbounded rate-limit state, outbound HTTP without explicit timeouts, image decode/resize on Tokio workers, inconsistent TTL bounds, and the account-linking unique-email collision found only via dynamic verification.
- See `references/ai-agent-audit-failure-patterns.md` for AI-agent failure patterns to hunt: context loss, lazy warning suppression, hallucinated docs, premature completion, tool misuse, and deterministic deployment requirements.
- Use `templates/DEPLOYMENT_GUIDELINES.md` when a backend root is missing `DEPLOYMENT_GUIDELINES.md`.

## High-Value Search Patterns

Search for these concepts and inspect context manually:

- Unsafe/soundness: `unsafe`, `transmute`, `from_raw`, `from_raw_parts`, `set_len`, `MaybeUninit`, `assume_init`, `zeroed`, `unsafe impl Send`, `unsafe impl Sync`, `extern "C"`.
- Panic DoS: `.unwrap()`, `.expect(`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, `[0]`, `.first().unwrap()`.
- SQL: `sql_query`, `query(`, `query_as(`, `format!("SELECT`, `format!("UPDATE`, `ORDER BY`, `LIMIT`, `OFFSET`, `ILIKE`, `IN (`, `push_str`, `bind(` missing.
- AuthZ: `user_id`, `tenant_id`, `role`, `is_admin`, `owner_id`, `claims`, `permissions`, `authorize`, `guard`.
- Async DoS: `std::fs`, `std::thread::sleep`, `Mutex`, `RwLock`, `spawn`, `spawn_blocking`, `join_all`, `fetch_all`, `collect::<Vec`, `Semaphore`.
- Network/SSRF: `reqwest`, `Url::parse`, `hyper`, `ureq`, `isahc`, `webhook`, `callback_url`, `avatar_url`, `import_url`.
- Files/commands: `PathBuf`, `.join(`, `.push(`, `canonicalize`, `Command::new`, `sh -c`, `temp_dir`, `NamedTempFile`.
- Secrets: `DATABASE_URL`, `JWT_SECRET`, `API_KEY`, `TOKEN`, `password`, `secret`, `Authorization`, `Cookie`.
- Dead code / AI cruft: `allow(dead_code)`, `allow(unused`, `expect(unused`, `allow(clippy`, `dead_code`, `TODO`, `FIXME`, `stub`, `placeholder`, `legacy`, `compat`, `not used yet`.
- Project policy: `Uuid::new_v4`, `Uuid::now_v7`, `uuidv7`, `uuidv8`, `gen_random_uuid`, `SERIAL`, `BIGSERIAL`, `postgres:`, `postgresql`, `POSTGRES_VERSION`, `DATABASE_URL`.
- Deployment/env safety: `.env.example`, `docker-compose`, `Dockerfile`, `DEPLOYMENT_GUIDELINES.md`, `password`, `secret`, `changeme`, `admin`, `postgres`, `sslmode=disable`, `latest`.
- AI: `openai`, `anthropic`, `llm`, `prompt`, `system_prompt`, `embedding`, `vector`, `rag`, `tool_call`, `function_call`, `memory`.
- OAuth/OIDC: `id_token`, `access_token`, `userinfo`, `nonce`, `state`, `code_challenge`, `code_verifier`, `pkce`, `redirect_uri`, `aud`, `iss`, `jwks`, `kid`, `alg`, `decode(`, `Validation::`, `insecure_disable_signature`.
- Sessions/identity: `token_hash`, `revoke`, `revoke_all`, `banned_at`, `disabled_at`, `email_verified`, `provider_user_id`, `find_by_email`, `link(`, `bootstrap`, `is_owner`, `exchange_code`.
- Crypto/constant-time: `== ` near `hmac`/`mac`/`sig`/`token`/`hash`, `verify_slice`, `ConstantTimeEq`, `subtle`, `getrandom`, `thread_rng`, `OsRng`, `aes-gcm`, `chacha20`, `zeroize`, `.len() >= 32`, `cookie_secret`, `signing_key`.
- DB deep: `SET ROLE`, `SET search_path`, `current_setting`, `set_config`, `ROW LEVEL SECURITY`, `BYPASSRLS`, `SECURITY DEFINER`, `COPY`, `pg_advisory_lock`, `dblink`, `postgres_fdw`, `pgbouncer`, `statement_cache`, `CONCURRENTLY`, `ALTER TABLE`, `migrate!`.
- Web/middleware/webhooks: `route_layer`, `.layer(`, `CorsLayer`, `allow_origin`, `allow_credentials`, `DefaultBodyLimit`, `catch_panic`, `TimeoutLayer`, `TraceLayer`, `X-Signature`, `X-Hub-Signature`, `Stripe-Signature`, `Bytes`.
- Deserialization/resource: `deny_unknown_fields`, `serde(flatten)`, `with_capacity(`, `.repeat(`, `bincode`, `ciborium`, `rmp_serde`, `load_from_memory`, `to_rgba8`, `ZipArchive`, `tar::`.
- Data lifecycle: `delete_account`, `purge`, `reaper`, `cleanup`, `export`, `unlink`, `audit_event`, `auth_event`.

## Common Pitfalls

1. **Calling SQL safe because it uses Rust.** Rust does not protect dynamic SQL identifiers or raw fragments.
2. **Ignoring panics.** In backends, panics can be remotely-triggered DoS.
3. **Reviewing only request handlers.** Many vulnerabilities sit in background workers that consume stored attacker data.
4. **Trusting JWT claims without server-side object checks.** A valid token does not authorize every object ID.
5. **Assuming SQLx/Diesel make every query safe.** Escape hatches and dynamic fragments still exist.
6. **Missing async blocking paths.** One blocking operation can become global degradation under load.
7. **Treating LLM output as a command.** The model is not a security boundary or policy engine.
8. **Skipping dependency build scripts.** Build-time compromise can steal CI secrets before runtime scans matter.
9. **Reporting vague findings.** Every serious finding needs code, impact, attacker chain, remediation, and verification.
10. **Overclaiming.** If exploitability depends on unknown deployment config, state the assumption and confidence.
11. **Static-only review.** Migrations, RLS, pool state, and constraint-collision bugs hide from reading; run them against a throwaway project-matching Postgres. Reading rated a real account-linking email collision "fine" - running it surfaced the 500.
12. **Trusting userinfo for identity.** Reading the profile from the userinfo endpoint without validating the ID token (`aud`/`iss`/`exp`/`nonce`) drops audience binding; `state` and `nonce` are different controls and both are required.
13. **Treating the ban as a feature, not a boundary.** If `verify()` doesn't check ban/disabled state on every request, a banned (or migrated-banned) user just re-logs-in.
14. **Counting characters as entropy.** A 32-char secret is not 256 bits; comparing secrets/MACs with `==` is a timing oracle. Use random bytes + constant-time compare.
15. **One static pass, no refutation.** Inflating plausible-but-unexploitable findings erodes trust; run the adversarial refute pass and label "real & exploitable" vs "defense-in-depth".

## Verification Checklist

- [ ] Scope and constraints stated.
- [ ] Audit directory `audit_DD-MM-AAAA-HH-MM/` created and report written there.
- [ ] Attack surface map completed.
- [ ] Backend markdown docs reviewed against code.
- [ ] `DEPLOYMENT_GUIDELINES.md` audited or created from template.
- [ ] database version policy checked across code/docs/deploy.
- [ ] identifier policy checked across code/docs/migrations.
- [ ] Dev/prod env examples checked for weak defaults and fail-closed behavior.
- [ ] Dependency/supply-chain checks completed or blockers stated.
- [ ] `unsafe` and panic paths reviewed.
- [ ] Dead code, `allow(dead_code)`, `allow(unused)`, broad `allow(clippy)`, and stale AI cruft reviewed.
- [ ] SQL construction and bind usage reviewed.
- [ ] Object/tenant authorization reviewed at query level.
- [ ] Transactions/race/idempotency reviewed.
- [ ] Pool/timeouts/body limits/rate limits reviewed.
- [ ] Secrets/TLS/DB privileges reviewed.
- [ ] SSRF/file/command surfaces reviewed.
- [ ] OAuth/OIDC flow reviewed: PKCE/state/nonce, ID-token aud/iss/exp validation, redirect_uri allowlist, mix-up.
- [ ] Session lifecycle reviewed: entropy, hash-at-rest, rotation, idle+absolute TTL, revocation/ban actually wired.
- [ ] Ban/disable enforced on every request, not just login.
- [ ] Federated identity linking reviewed: verified-email-only, per-provider trust, email canonicalization, unique-index collision, bootstrap race.
- [ ] Crypto reviewed: constant-time compares, key entropy vs length, key rotation, CSPRNG, secret hygiene/TLS.
- [ ] Connection-pool state bleed, RLS, and pgbouncer/prepared-statement interaction reviewed.
- [ ] Migration safety reviewed: no edits to applied migrations, locking, destructive/irreversible, role separation.
- [ ] Tower layer scope/ordering, body limits, panic-catch, timeouts reviewed.
- [ ] CORS (credentialed reflection / allowlist bypass) and security headers reviewed.
- [ ] Inbound webhook signature verification (raw body, constant-time, replay) reviewed.
- [ ] Deserialization/resource-allocation limits reviewed.
- [ ] Data lifecycle reviewed: deletion/export/erasure, unlink, session reaper, audit-event trail.
- [ ] Dynamic verification run against a throwaway project-matching Postgres when feasible (migrations apply + gated integration green), or blocker stated.
- [ ] AI/LLM surfaces reviewed if present.
- [ ] AI-agent failure artifacts reviewed even if the product has no AI feature.
- [ ] Findings ranked by severity and confidence.
- [ ] Each finding includes attacker chain and verification.
- [ ] Final report is detailed English markdown.
