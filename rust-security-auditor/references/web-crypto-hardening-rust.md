# Web/API Hardening, Cryptography, and Resource-Safety - Rust Reference

Companion to `backend-audit` for the transport/middleware/crypto layers. Tower/Axum/Actix specifics plus the crypto and deserialization classes the base skill under-covers.

## A. Tower / middleware layering bugs (Axum/Tower)

Order and scope of layers is security-relevant:
- **Layer scope**: `Router::layer` wraps the whole router; `route_layer` only wraps matched routes and does NOT run for 404s. Auth/rate-limit applied via the wrong one either over- or under-covers. Verify the auth/rate-limit/body-limit layers actually cover the intended routes (and that fallback/404 paths are acceptable).
- **Ordering**: middleware runs outer→inner on request. A rate limiter must sit OUTSIDE expensive auth/DB work to protect it. A body-limit must be outer to anything that buffers the body. CORS placement affects preflight handling.
- **`DefaultBodyLimit`**: Axum has a default (2MB) but custom extractors / `Bytes`/`Multipart` / raw streams can bypass expectations. Confirm an explicit limit per route, especially uploads.
- **`CatchPanic` / panic→500**: without a panic-catching layer, a panic in a handler aborts the connection task; with `panic=abort` it can take the worker/process. Recommend `tower_http::catch_panic` so a reachable panic is a 500, not a crash - but it's a mitigation, not a license to leave panics.
- **`TimeoutLayer` + `ConcurrencyLimitLayer` + `LoadShed`**: outbound and inbound timeouts; per-route concurrency caps for expensive flows; load-shed to fail fast under overload.
- **`TraceLayer` leakage**: default request/response tracing can log `Authorization`, `Cookie`, tokens, query strings with secrets. Verify header/field redaction.
- **Extractor failure mapping**: a custom `FromRequestParts` that returns a verbose error can leak internals; failures should map to safe statuses.

## B. CORS - the credentialed-reflection traps

- **Reflect-Origin + `Allow-Credentials: true`** = any site can make credentialed cross-origin requests and read responses → token/data theft. Never reflect arbitrary Origin with credentials.
- **Wildcard `*` with credentials** is spec-invalid but some hand-rolled middleware emits it anyway - check.
- **Allowlist by `starts_with`/`contains`/regex** → `https://app.example.com.evil.com` or `https://evil-app.example.com` bypass. Match the full origin exactly against a configured set.
- **`null` origin** accepted (sandboxed iframes, `file://`) → treat as untrusted.
- **Missing `Vary: Origin`** with a dynamic ACAO → cache poisoning across origins.
- Header-bearer auth (token in `Authorization`, not a cookie) reduces CORS/CSRF blast radius - but a future switch to cookie auth silently makes a permissive CORS dangerous. Flag "no explicit, restrictive CORS policy" as a regression risk even when not exploitable today, and assert it with a test.

## C. Security response headers

Flag when missing on a production API/SPA origin (set via a Tower layer):
- `Strict-Transport-Security` (HSTS) on HTTPS.
- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY` / `Content-Security-Policy: frame-ancestors 'none'` for non-embeddable surfaces.
- `Referrer-Policy: no-referrer` / `strict-origin-when-cross-origin` (also limits token-in-URL leakage).
- `Cache-Control: no-store` on authenticated/sensitive responses (avoid caching tokens/PII).
- `Content-Security-Policy` for any HTML the backend serves.
- `Permissions-Policy`, and `Cross-Origin-Opener-Policy`/`-Resource-Policy` where relevant.

## D. CSRF and cookies

- Cookie auth + state-changing routes need CSRF defense (`SameSite=Lax/Strict` is a baseline but not complete for all methods; add double-submit or origin checks for sensitive POSTs).
- Cookie attributes: `HttpOnly`, `Secure` (gated on the API's own scheme, not a different app URL's), `SameSite`, scoped `Path`/`Domain`. The `__Host-` prefix requires `Secure` + `Path=/` + no `Domain` (incompatible with a scoped `Path` like `/auth` - note the trade-off).
- Set `Secure` from an explicit production flag, not by string-prefixing a base URL - behind a TLS-terminating proxy the app may see http.

## E. Inbound webhooks (signature verification) - commonly broken in Rust

- **Verify the signature over the RAW request body bytes**, before/without JSON re-serialization. Axum/Actix bug pattern: extract `Json<T>`, then re-serialize to verify → signature fails or, worse, verification is skipped. Capture the raw `Bytes` first (custom extractor / `body::to_bytes`), verify HMAC, THEN parse.
- **Constant-time compare** the signature (`subtle`/`ConstantTimeEq` or the provider SDK), never `==` on the hex/base64 string.
- **Replay window**: verify the provider timestamp and reject old requests; store processed event IDs for idempotency.
- **Secret per source**, rotated; reject unsigned/wrong-version signatures.
- Outbound webhooks: SSRF controls (covered in SKILL.md) + sign your own outbound payloads so receivers can verify.

## F. Cryptography and constant-time (Rust specifics)

- **Constant-time comparison**: use `subtle::ConstantTimeEq` for comparing MACs, signatures, tokens, password-hash outputs (or the hashing crate's `verify`). `a == b` on `&[u8]`/`String` short-circuits → timing oracle. HMAC: use the MAC's own `verify_slice` (constant-time) rather than computing and `==`-comparing tags.
- **Key length vs entropy**: a "32-character" secret is NOT 256 bits unless it's 32 random *bytes*. A config that floors `cookie_secret.len() >= 32` measures characters, not entropy - a 32-char human passphrase is far weaker. Require base64/hex of ≥32 random bytes and validate the decoded byte length.
- **Key rotation**: a single signing key with no `kid` and no dual-key verify window means rotation breaks all in-flight tokens/cookies and is therefore avoided. Recommend: sign with primary key, verify against [primary + previous] during a rotation window.
- **AEAD nonce reuse**: with `aes-gcm`/`chacha20poly1305`, a reused (key, nonce) pair is catastrophic. Verify nonces are random/counter and never reused; prefer XChaCha20 for random nonces.
- **CSPRNG**: secrets/tokens/keys from `getrandom`/`rand::rngs::OsRng`, never `rand::thread_rng()` for long-lived secrets without OS seeding guarantees, never `SmallRng`/seeded PRNGs.
- **Password hashing**: Argon2id with sane params (memory/iterations/parallelism), per-password salt, `argon2`/`scrypt`/`bcrypt` crates' `verify` (constant-time). No SHA/MD5/plain. OAuth-only services have no passwords - confirm no dead password path exists.
- **Secret hygiene in memory**: `zeroize`/`Zeroizing` for key material; avoid `Debug`/`Display` derives that print secrets (verify redacted `Debug` impls on config/secret structs); secrets not in panic messages or error `Display`.
- **TLS**: prefer rustls over native-tls/OpenSSL (fewer footguns, no system OpenSSL backports gap). Remote Postgres/Redis must use TLS with verification (`sslmode=verify-full`), not `disable`/`prefer`/`require`-without-verify.

## G. Deserialization and resource-allocation attacks

- **serde recursion / stack overflow**: deeply nested JSON/YAML can overflow the stack (panic/abort). `serde_json` has a default recursion limit (128) - verify custom deserializers, other formats (YAML via `serde_yaml`, TOML), and `serde_json::Value` trees don't bypass it; cap nesting/size at the edge.
- **Length-prefix allocation bombs**: `bincode`, `postcard`, CBOR (`ciborium`), MessagePack decode a length prefix and may `Vec::with_capacity(huge)` before reading → OOM. Use the format's size-limit / `with_limit` options; never deserialize untrusted bytes without a byte cap.
- **`#[serde(deny_unknown_fields)]`** on security-sensitive DTOs to stop mass-assignment/over-posting; beware it's incompatible with `flatten`.
- **Untagged enums / `flatten` + `serde_json::Value`**: ambiguous parsing and arbitrary-key ingestion merged into internal state = mass assignment (`role`, `tenant_id`, `is_admin`, `balance`). Use typed DTOs distinct from DB models.
- **`Vec::with_capacity(user_len)` / `String::repeat(user_n)` / pre-sizing from a header/length field**: bound it.
- **Decompression / image / archive bombs**: cap decompressed size and source pixels/dimensions before allocating (image decode is `w*h*4`); run CPU-heavy decode in `spawn_blocking` with a concurrency semaphore; zip/tar slip + uncompressed-size caps.
- **Multipart**: per-field and total size limits, field-count limit, filename sanitization.

## H. Rate limiting that actually works

- In-memory per-instance limiters are bypassed by horizontal scaling (N replicas → N× the limit) and lost on restart. For real limits use a shared store (Redis token bucket) or enforce at the edge/gateway; note the limitation explicitly when only in-memory exists.
- Key on the trusted client identity (socket peer, or `X-Forwarded-For` ONLY when the immediate peer is a configured trusted proxy) - never on a raw spoofable header. Bound/TTL-evict the key map.
- Apply stricter budgets to expensive/abusable endpoints: login, OAuth callback (drives provider round-trips), token/exchange, password reset, email/SMS send, search, export, signup.

## I. Denial-of-wallet / cost abuse (beyond LLM)

Any user-triggerable expensive external action is a cost-abuse vector: transactional email/SMS/push sends, third-party API calls with per-call cost, S3 PUT/GET storms, CDN purges, image processing, embeddings. Require per-user budgets, rate limits, and (for high-cost/irreversible actions) confirmation. Unbounded `tokio::spawn` per request is a memory/cost amplifier.
