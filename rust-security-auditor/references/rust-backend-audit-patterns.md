# Rust Backend Audit Patterns Captured from a Real Review

Use this as a compact reference when applying `backend-audit` to Rust/Axum/PostgreSQL services.

## High-value chains to check

### Spoofable proxy headers plus in-memory rate limiting

Risk pattern:

- A rate limiter keys clients from `X-Forwarded-For` or `X-Real-Ip` without first proving the immediate peer is a trusted proxy.
- The limiter uses an unbounded `HashMap<String, ...>` for per-client buckets.
- Auth or other unauthenticated routes sit behind that limiter.

Attacker chain:

1. Send unauthenticated requests with a new `X-Forwarded-For` value each time.
2. Bypass per-client limits because every request gets a fresh key.
3. Grow the limiter map without bound.
4. Use the bypass to reach downstream expensive paths, such as DB checks or external OAuth calls.

Audit questions:

- Does the service use the real socket peer address, or arbitrary headers?
- Are forwarded headers trusted only when the immediate peer is in configured trusted proxy CIDRs?
- Are invalid client keys rejected or normalized to an IP address?
- Is the bucket map bounded or TTL-evicted?
- Are expired/empty buckets removed?

Fix direction:

- Extract peer IP from connection info by default.
- Trust `Forwarded`/`X-Forwarded-For` only behind configured trusted proxies.
- Bound rate-limit state with a TTL cache or explicit max cardinality.
- Add global concurrency limits for expensive unauthenticated flows.

### Outbound HTTP calls without explicit timeouts

Risk pattern:

- `reqwest::Client::new()` is used in request-path integrations, especially OAuth, webhooks, CDN APIs, avatar fetchers, or LLM APIs.
- No connect timeout, total request timeout, redirect policy, or route-level timeout exists.

Attacker chain:

1. Drive public routes that perform outbound calls.
2. Combine with weak/bypassable rate limiting.
3. Slow or stalled remote services leave futures pending.
4. Runtime resources, sockets, request slots, or provider quotas are consumed until login/API availability degrades.

Fix direction:

```rust
reqwest::Client::builder()
    .connect_timeout(std::time::Duration::from_secs(3))
    .timeout(std::time::Duration::from_secs(8))
    .pool_idle_timeout(std::time::Duration::from_secs(30))
    .redirect(reqwest::redirect::Policy::none())
    .build()?;
```

Also consider Tower `TimeoutLayer`, `ConcurrencyLimitLayer`, and a per-integration semaphore.

### Image decode/resize work inside async handlers

Risk pattern:

- Upload bytes are size-limited, but decoded source dimensions or source pixels are not.
- Code calls `image::load_from_memory`, `to_rgba8`, resize, or encode inline in an async path.
- Output dimensions are capped, but source decompression cost is not.

Attacker chain:

1. Upload a small compressed image with huge dimensions or expensive decode behavior.
2. Backend decodes and allocates `width * height * 4` RGBA memory.
3. CPU-heavy decode/resize/encode runs on Tokio worker threads.
4. Concurrent uploads starve unrelated requests.

Fix direction:

- Decode dimensions first and reject over a source-pixel cap.
- Run CPU/image work in `spawn_blocking` or a bounded worker queue.
- Add an image-transform semaphore.
- Lower per-feature upload byte limits where possible.

### Bounded TTL config consistency

Risk pattern:

- Some TTLs are range-checked, but adjacent security TTLs are parsed without bounds.
- OAuth state, exchange code, invite, reset-token, webhook replay, and session TTLs should all fail closed on invalid ranges.

Fix direction:

- Apply explicit lower/upper bounds to every security lifetime.
- Test absent, valid, zero, negative, and too-large values.

### Account-linking unique-email collision (found only via dynamic verification)

Risk pattern:

- Federated login auto-links a second provider to an existing account by verified email, gated by a provider allowlist (e.g. only Google auto-links).
- When the provider is NOT on the allowlist, the code falls through to "create a new account" - but still tries to claim the verified email on the new user row.
- The email is already owned by the first account; a `lower(email)`/`citext` unique index rejects it.
- The conflict-recovery branch only handles the username constraint, not the email constraint.

Result: login for an untrusted-provider user whose email matches an existing account hard-fails with a 409/500 (`Conflict(users_email_lower_key)`). Pure static review rated the linking logic "fine"; standing up a throwaway PG18 and running the gated integration test surfaced the crash immediately.

Fix direction:

- When auto-link is declined by policy, create the separate account WITHOUT claiming the email (record it on the identity row only, not the user row).
- Add a race backstop: on a `Conflict` whose constraint is the email index, retry creating the account with `email = None`.
- Always run identity/auth integration tests against a real Postgres, not just `cargo test` with no DB.

### ID-token audience binding vs blind userinfo trust

Risk pattern:

- After the code exchange, the backend reads identity from the provider's `userinfo` endpoint using the access token and never validates the `id_token` (no `aud`/`iss`/`exp`/`nonce` check).
- `email_verified` and `sub` are therefore taken from an unauthenticated GET, with no proof the token was issued to OUR client.

Exploitability: not directly exploitable with a strict server-side auth-code exchange (client_secret + PKCE + fixed redirect_uri bind the code to us), so rate it defense-in-depth - but it becomes live the moment any path accepts a caller-supplied token, and it pairs with the account-linking takeover (an over-asserted `email_verified` links into a victim).

Fix direction:

- Validate the `id_token` from the token-endpoint response: `aud` contains `client_id`, `azp == client_id` when present, exact `iss`, `exp` in future, `nonce` matches. Take `sub`/`email`/`email_verified` from it. No JWKS needed for token-endpoint responses (OIDC Core §3.1.3.7) - but never run a signature-skipping decoder on a caller-supplied JWT.

### Ban gate must run on every request

Risk pattern:

- `verify()` checks only that the session is live and the user row exists; it never consults `banned_at`/`disabled_at`.
- Bans (or bans migrated from a predecessor system) are unenforceable: the user re-runs OAuth and gets a fresh session, and even `revoke_all_for_user` is defeated by the next login.

Fix direction:

- Re-check account status on every `verify()` (and at login/exchange), mapping banned → 403. Add a denormalized `banned_at` checked in the auth path even before a full moderation subsystem exists.

## Report practice

- State exact commands that were run and exact blockers for missing tools. Do not imply `cargo audit` or `cargo deny` ran when they were not installed.
- Include the most dangerous combined chain in the executive summary, not just isolated findings.
- Keep the chat-facing summary concise; put the detailed audit in the English markdown report. Match the project's or maintainer's preferred summary language when one is stated.
