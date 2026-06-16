# Caches, CDNs, Queues, GraphQL & gRPC Security

Companion to `backend-audit` for the surfaces that sit outside normal CRUD auditing: HTTP/CDN caches, Redis, message queues/streams, GraphQL, and gRPC. Adds the cross-user-leakage, replay, cost-abuse, poisoning, hidden-authz, and DoS classes the base SKILL.md and sibling references do not cover. Activate per surface present. For middleware/headers/rate-limiting see `references/web-crypto-hardening-rust.md`; for async DoS see `SKILL.md` §4 ("Async Runtime Starvation and Blocking Hazards").

## A. Web cache poisoning & deception (CDN / reverse proxy / `tower-http` cache)

A shared cache (CDN, Varnish, nginx, Cloudflare) keys a response by a subset of the request; anything that influences the body but is NOT in the key is an **unkeyed input** an attacker can weaponize.

Red flags:
- Authenticated/tenant-specific responses are cacheable. Check `Cache-Control`/`Surrogate-Control` vs the presence of `Authorization`/`Cookie`/`X-Tenant-*`/per-user dimensions. A missing or wrong `Vary` (no `Vary: Authorization, Cookie`) on a user-specific body = one user's response served to another. **Cross-tenant cache leak is CRITICAL** (CWE-524 use of cache containing sensitive info; CWE-525 browser-cache variant; set `Cache-Control: no-store` per `references/web-crypto-hardening-rust.md` §C).
- Unkeyed inputs that change the body: `Host`, `X-Forwarded-Host`, `X-Forwarded-Scheme/-Proto`, `X-Original-URL`/`X-Rewrite-URL`, `X-Forwarded-For`, custom routing headers, and query params dropped from the key. If the app reflects `X-Forwarded-Host` into a link/redirect/`<base>`, an attacker poisons it for all cache hits.
- Path normalization disagreement: cache and origin parse `/`, `;`, `%2e`, trailing dots, or extensions differently -> **web cache deception**. A static-looking path (`/account/profile.css`, `/api/me/nonexistent.js`) that the origin still resolves to dynamic authed content gets cached publicly (Cached-and-Confused class).
- Cacheable redirects or error pages built from attacker-controlled input (reflected `Host`/path in a 301/302 `Location` or a 404 body).
- Cache key omits the part of the URL that selects the tenant (path-based tenancy `/{tenant}/...` not in the key).

Correct pattern:
- `private, no-store` (or `no-cache` + correct `Vary`) on every authenticated/tenant response; the cache must never store principal-specific bodies on a shared key.
- Build absolute URLs/redirects from a configured canonical host, never from inbound `Host`/`X-Forwarded-*`.
- Make cache and origin agree on normalization; deny caching by content type/route, not by file-extension heuristics. Audit with PortSwigger Param Miner methodology (unkeyed-input discovery).

## B. Redis / application cache (`deadpool-redis`, `fred`, `bb8-redis`)

Required checks:
- **Never internet-exposed.** Bind to private interface; in K8s enforce a `NetworkPolicy`; the AWS/GCP security group must not allow 6379 from 0.0.0.0/0. Run `redis-cli -h <host> CONFIG GET requirepass` mentality: default no-auth Redis on a routable IP = full read/write.
- AuthN/Z: require `requirepass` AND ACL named users (`ACL SETUSER`) scoped to needed commands/key patterns - not the all-powerful `default` user. Disable/rename dangerous commands (`FLUSHALL`, `CONFIG`, `KEYS`, `DEBUG`, `MODULE`, `SCRIPT`) via `rename-command`. `EVAL`/Lua and `FUNCTION` are RCE-adjacent - restrict.
- **TLS across any network boundary** (`rediss://`, cert verification on). Plaintext `redis://` over a network = creds and PII on the wire.
- No default/blank creds; secret from env/secret-store, not source.
- **Tenant-aware key prefixes**: every key namespaced by `tenant_id`/`user_id` (`t:{tenant}:sess:{id}`). A shared key like `user_profile:{email}` across tenants leaks cross-tenant. Cross-tenant cache read is CRITICAL.
- **Cache-key injection**: keys built by concatenating user-controlled fragments without delimiter escaping -> `a` + `:b` collides with `a:` + `b`, letting one user poison/read another's entry. Hash or strictly encode user fragments; never trust raw user input as a key segment.
- Intentional TTL on every entry and a sane `maxmemory` + `maxmemory-policy` (e.g. `allkeys-lru`/`volatile-ttl`); a cache with no eviction policy and no TTL is an OOM/availability bug (CWE-770). Session/lock keys must have TTL so a crash can't strand state forever.
- No raw secrets/PII in a shared cache unless encrypted; flag tokens/PANs/emails cached in plaintext.

## C. Queues / streams / event-driven (RabbitMQ `lapin`, Kafka `rdkafka`, SQS `aws-sdk-sqs`)

**Treat every consumed message as UNTRUSTED at the consumer boundary** - internal does not mean trusted. A compromised/buggy producer, a poisoned DB row that drives a producer, or a replayed message all reach the consumer. CWE-20 applies inside the bus.

Consumer-side required checks:
- Validate message schema AND size before processing (a giant or malformed payload OOMs/panics the worker). Reject unknown message types/versions; version your envelope.
- **Idempotency**: handlers keyed by an idempotency/dedup key (message id, business key) so at-least-once delivery (SQS, Kafka, RabbitMQ redelivery) doesn't double-charge/double-send. Persist processed ids.
- **Replay protection**: reject stale/duplicate messages (timestamp window + dedup store); a captured message must not be replayable for effect.
- **Bounded retries + dead-letter queue.** A poison message with infinite redelivery is a CPU/throughput DoS (poison-message retry storm). Flag: no DLQ, no max-receive-count (SQS `maxReceiveCount`/`RedrivePolicy`), no retry cap, or retries with no backoff.
- No secrets / no raw PII in message bodies (they persist in the broker, DLQ, and logs); pass a reference/handle and fetch with authz, or encrypt the payload.

Transport & perms:
- Least privilege split: producer can publish to its topics/queues only; consumer can read+ack its own - not admin/`*`. RabbitMQ: per-vhost user with scoped configure/write/read regexps (RabbitMQ access-control model). Kafka: per-principal topic/group ACLs. SQS: tight resource-scoped IAM policy + queue policy (deny non-TLS via `aws:SecureTransport`).
- TLS in transit; mTLS (Kafka `ssl`/SASL, RabbitMQ peer verification) across trust boundaries. No anonymous/guest access reachable off-host (RabbitMQ `guest` is loopback-only by default via `loopback_users` - verify it stays that way).

## D. GraphQL (`async-graphql`, `juniper`)

GraphQL collapses many endpoints into one POST, so per-endpoint rate limits and gateway authz do not protect it. CWE-770 is the dominant DoS class here.

Required checks:
- **Query depth limit** and **cost/complexity limit** enforced server-side. `async-graphql`: `.limit_depth(n)` and `.limit_complexity(n)` on the schema builder; without them a recursive/nested query is an unbounded-work DoS.
- **Pagination/amount caps**: every list resolver caps `first`/`last`; reject or clamp huge values. Unbounded `first: 1000000` plus nesting multiplies.
- **Introspection + GraphiQL/Playground disabled or restricted in prod** (`async-graphql` `SchemaBuilder::disable_introspection`; don't mount the IDE route in prod). Leaked schema accelerates attacks but is not itself the vuln - still flag.
- **Resolver-level authorization**: authz checked IN each resolver (or via a guard), not only at the HTTP gateway. A single GraphQL endpoint behind one auth check still exposes every field/mutation - per-field/per-mutation checks are required. Field-level authz on sensitive properties (`user.email`, `account.balance`, admin-only fields) via `#[graphql(guard = ...)]`.
- **Redact internal errors**: map resolver errors to safe messages; don't return DB errors, file paths, or backtraces. Disabling introspection doesn't hide field names leaked through suggestion/error text - verify error extensions are sanitized.
- **Batching abuse**: query **aliases** (`a: user(id:1) b: user(id:2) ...`) and **array batching** (a JSON array of operations) multiply work in ONE HTTP request and bypass per-request rate limits and naive login throttles (alias-based credential stuffing). Cap aliases/operation count, disable array batching unless needed, and rate-limit by cost not request count (per OWASP GraphQL Cheat Sheet). Real-world pattern: "alias amplification" - a single request repeats an expensive resolver via many aliases, multiplying work past a missing cost/complexity limit (verify any specific CVE against the vendor advisory before citing it).

## E. gRPC (`tonic`)

Required checks:
- **TLS / mTLS** where appropriate (`tonic` `ClientTlsConfig`/`ServerTlsConfig`; rustls backend). Plaintext h2c only on a trusted localhost/mesh boundary.
- **Auth interceptor applied to EVERY service**, consistently. A common bug: interceptor wired on one service but a second service on the same `Server` is unauthenticated. Verify each `add_service` is covered.
- **Per-RPC authorization**, not just connection/channel-level. A valid mTLS client or a valid token is authN, not authZ - each method must check the caller may perform it.
- **Deadlines/timeouts** set (server `Server::timeout`, and honor client deadline) so a slow/abandoned RPC can't pin a task indefinitely (ties to `SKILL.md` §4 async DoS).
- **Max message size** (`max_decoding_message_size` / `max_encoding_message_size`) - the tonic default is 4 MiB for decoding (encoding default is `usize::MAX`); if compression (gzip) is enabled, the decode size limit is the **decompression-bomb** guard. A multi-GB message with no decode cap = OOM (CWE-770). Set explicit caps; bound compression.
- **Validate protobuf fields explicitly.** proto3 implicit-presence scalars default to zero values and unknown `enum` values map to the 0 enumerator - a missing/garbage field silently becomes `0`/`""`/default, not an error (and you can't tell "set to default" from "absent" without `optional`). Validate presence, ranges, enum validity, and repeated-field/`map` sizes in code; never trust proto wire validation for business invariants.
- **Restrict admin/introspection surfaces in prod**: server **reflection** (`tonic-reflection`), **channelz**, and health/admin services expose the API shape and internals - gate or disable for untrusted networks.
- **Normalize + validate metadata** (gRPC headers): treat `authorization`, tenant, and routing metadata as untrusted input; metadata keys are case-insensitive ASCII and binary (`-bin`) values are base64 - validate/decode safely and don't trust client-set routing/identity metadata.

## F. Worker safety (extends `SKILL.md` §4 async DoS)

- **Bounded concurrency** on consumers: a `Semaphore` / fixed worker pool / `buffer_unordered(n)` so a burst of messages doesn't spawn unbounded tasks (memory blowup). Never `tokio::spawn` per message without a cap.
- **Per-message timeout** so one stuck handler can't wedge a worker; combine with the retry/DLQ policy in §C so a timeout becomes a bounded retry, not an infinite loop.
- **Backpressure**: prefetch/`basic.qos` (RabbitMQ), `max.poll.records` (Kafka), bounded SQS in-flight; a worker that pulls faster than it processes builds an unbounded in-memory backlog. Bound channels (`mpsc::channel(n)`, not `unbounded_channel`) between fetch and process stages.
- CPU-heavy message work in `spawn_blocking` behind a concurrency limit (see `references/web-crypto-hardening-rust.md` §G).

## Sources

- PortSwigger - Web Cache Poisoning: https://portswigger.net/web-security/web-cache-poisoning
- Redis - Security: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
- RabbitMQ - Access Control: https://www.rabbitmq.com/docs/access-control
- Apache Kafka - Security: https://kafka.apache.org/documentation/#security
- AWS - Amazon SQS Security: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security.html
- OWASP - GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- gRPC - Authentication: https://grpc.io/docs/guides/auth/
- CWE-524 / CWE-525 / CWE-770: https://cwe.mitre.org/data/definitions/524.html , https://cwe.mitre.org/data/definitions/525.html , https://cwe.mitre.org/data/definitions/770.html
