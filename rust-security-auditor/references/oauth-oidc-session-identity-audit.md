# OAuth 2.0 / OIDC, Sessions, and Federated Identity - Deep Audit Reference

Authoritative companion for the auth portion of `backend-audit`. Rust backends frequently get the *framework* right and the *protocol* wrong. Treat this as the checklist when a service does "Sign in with Google/Twitch/GitHub", issues sessions, or links accounts.

Specs to reason against (cite them in findings):
- RFC 6749 (OAuth 2.0), RFC 6750 (Bearer), RFC 7636 (PKCE), RFC 9700 (OAuth 2.0 Security BCP - supersedes the older security-topics draft), RFC 9207 (`iss` authorization-response param / mix-up), RFC 7009 (token revocation).
- OpenID Connect Core 1.0 (esp. §3.1.3.7 ID Token validation), OIDC nonce semantics.
- RFC 8725 (JWT BCP).

## A. Authorization-code flow integrity

Red flags / required checks:
- **PKCE**: public clients (SPA/mobile) MUST use PKCE with `S256` (never `plain`). The `code_verifier` must be 43–128 chars of high entropy, stored server-side or in a signed/encrypted cookie, and sent on the token exchange. Confidential server clients should still use PKCE when the provider supports it (defense-in-depth per RFC 9700). Twitch does not support PKCE → rely on client_secret + `state` + `nonce`.
- **`state`**: high-entropy, single-use, bound to the user's browser (signed cookie or server session). It is CSRF defense for the callback. Missing/static/predictable `state`, or `state` not compared to the cookie, is **login-CSRF** (attacker logs victim into attacker's account).
- **`nonce` (OIDC)**: distinct from `state`. Sent in the authorize request, must equal the `nonce` claim of the returned `id_token`. It is the *replay* binding for the ID token. A flow that validates the ID token but never sent/checked a `nonce` is incomplete.
- **redirect_uri**: must be an exact-match allowlist on the provider side AND not attacker-influenced on our side. Watch for dynamic redirect_uri from request input, or "open redirect" on the *final* hop where we bounce the browser to an app URL built from user input.
- **Authorization code**: single-use, short-lived, bound to our `client_id` + `redirect_uri` + PKCE verifier. The token exchange must use our `client_secret` (confidential client). This binding is what prevents code injection/substitution.
- **Mix-up attack (RFC 9207)**: with multiple providers, validate the `iss` authorization-response parameter (or per-provider distinct redirect_uri) so a code minted by provider A cannot be redeemed against provider B's token endpoint.

## B. ID token validation - the audience-binding trap (high-value finding)

The recurring real-world bug: the backend does the code exchange, then reads the profile from the **userinfo** endpoint using the returned access token, and **never validates the `id_token`** (or never checks `aud`). This drops audience binding - the assurance that the token was issued to *our* `client_id`. It is the OIDC analogue of the "confused deputy" / token-substitution problem.

When exploitable: directly exploitable if the endpoint ever accepts a caller-supplied access_token/id_token (implicit flow, "login with token" APIs, mobile flows). With a strict server-side auth-code exchange (client_secret + PKCE + fixed redirect_uri) it is usually NOT directly exploitable today, because a code minted for another client can't be redeemed here - but it is a real defense-in-depth gap and becomes live the moment that flow assumption changes. Rate it MEDIUM-as-hardening / HIGH-if-token-accepted; always explain which.

Required validation (OIDC Core §3.1.3.7), in deterministic Rust:
- `aud` contains our `client_id` (string or array); `azp` == `client_id` when present (multi-audience).
- `iss` exactly equals the provider's known issuer (Google: both `https://accounts.google.com` and `accounts.google.com`; Twitch: `https://id.twitch.tv/oauth2`).
- `exp` in the future (small leeway for skew); `iat`/`nbf` sane.
- `nonce` equals the value we minted.
- Take identity (`sub`), `email`, `email_verified` from the **validated id_token**, not from an unauthenticated userinfo GET.

JWKS without a stack: OIDC Core §3.1.3.7 permits skipping signature verification when the id_token is received **directly from the token endpoint over TLS** (the TLS channel authenticates the source). So a dependency-free fix is to decode the JWT payload and check `aud`/`iss`/`exp`/`nonce` - but the SECURITY INVARIANT is that this is sound *only* for token-endpoint responses. Never run a signature-skipping decoder on a caller-supplied JWT, on a token from the front channel, or on refresh-derived tokens delivered via the browser. If tokens ever arrive untrusted, full JWKS signature verification (`jsonwebtoken` + key cache, alg pinned to the provider's `RS256`/`ES256`) is mandatory.

## C. JWT-as-session pitfalls (RFC 8725)

If the service uses self-issued JWTs as sessions:
- `alg` confusion: reject `none`; pin the expected algorithm family. Classic break: server verifies with a key that can be used as both RSA public key and HMAC secret → attacker signs `HS256` with the known RSA *public* key. Verify the alg matches the key type.
- `kid` injection: `kid` from the token used to look up a key via filesystem path or SQL → path traversal / SQLi. Allowlist `kid`.
- Embedded `jwk`/`jku`/`x5u`: never trust keys carried in the token; ignore those headers.
- No revocation: JWT sessions can't be revoked without a denylist - flag "logout/ban does not actually invalidate live JWTs". Prefer opaque server-side sessions when revocation matters (bans, streamers/mods).
- Token in URL/query (logged, in Referer, in history). Tokens belong in `Authorization` headers or the URL **fragment** consumed once and stripped.

## D. Opaque session lifecycle

- Entropy: ≥128, prefer 256 bits from the OS CSPRNG (`getrandom`), URL-safe encoded. Store only a hash (SHA-256 acceptable for high-entropy random tokens - no salt needed because the input space is uniform and un-bruteforceable; per-token salt/pepper adds little but is not wrong).
- Lookup is by exact hash equality; a SQL `WHERE token_hash = $1` on a unique index is not constant-time but is not a practical oracle for a 256-bit secret (attacker can't iteratively construct a preimage). Note it, don't over-rate it.
- Expiry/revocation evaluated in SQL against the server clock (`now()`), so a skewed app clock can't extend a session. `revoked_at` makes logout/ban instant.
- Rotation: rotate the session token at privilege boundaries (login, step-up, role change) to limit fixation. Absolute TTL plus idle timeout; 30-day absolute with no rotation/idle is long for a bearer - flag it.
- "Log out everywhere" / ban must actually revoke: a `revoke_all_for_user` that exists but is never called on ban is dead code and a finding.
- Token delivery to SPAs: a one-time, short-lived exchange code in the callback fragment, POSTed back over CORS to mint the real bearer (returned in the JSON body), keeps the long-lived token out of browser history/Referer. Bearer stored in JS is XSS-exposed regardless - note the trade-off.

## E. The ban/disable gate (auth boundary, not a feature)

- A `verify()` that checks only session liveness (not revoked, not expired, user row exists) but never consults `banned_at`/`disabled_at`/suspension is a CRITICAL gap when the product has bans: a banned user simply re-logs-in via OAuth and gets a fresh session. Re-check account status on **every** `verify()`, not just at login, so an active session dies mid-flight when a ban lands.
- For data migrated from a predecessor system, banned users carry over: their ban must be enforced by the new auth layer or it is silently lifted. Add a denormalized `banned_at` checked in the auth path even before the full moderation subsystem exists.

## F. Federated identity & account linking (takeover surface)

- **Verified-email-only linking**: linking a second provider to an existing account by email is safe ONLY when the new provider asserts `email_verified == true` AND that assertion is trustworthy. An unverified email must never link or even be persisted onto the account (it could squat the unique-email slot).
- **Per-provider trust policy**: not all providers verify email ownership equally. Gate auto-link behind an explicit allowlist of providers whose `email_verified` you accept (and optionally a domain allowlist). A new provider added later must be vetted before it can auto-link - default-deny.
- **email_verified must be authoritative**: prefer it from the validated id_token, not an unauthenticated userinfo response (ties back to §B).
- **Email canonicalization mismatches**: case-insensitive uniqueness via `lower(email)` or `citext` is the baseline. Gmail dot/`+tag` variants map to one mailbox but are distinct strings; deciding to canonicalize them is a product call but DIVERGING from the predecessor system can split or merge migrated accounts - flag the inconsistency either way. IDN/Unicode homoglyph and confusable domains can defeat naive uniqueness - NFC-normalize and consider a confusables check for security-relevant emails.
- **Unique-index collision on create**: when auto-link is *declined* by policy but the verified email already belongs to another account, naive `create_new_user` will try to claim the email and hit the unique index → the login hard-fails (500/409). Correct behavior: create the separate account WITHOUT claiming the email (record it on the identity row only). Watch for conflict-recovery that only handles the username constraint and not the email constraint.
- **Bootstrap/owner promotion races**: "first verified login with EMAIL becomes owner while no owner exists" is a check-then-set TOCTOU. Use a conditional `UPDATE ... WHERE NOT EXISTS (SELECT 1 ... role='owner')` and require `email_verified` + exact match. Audit whether it can re-fire.
- **Provider `sub` stability**: relying on the provider subject id as the durable identity key is correct (Google `sub` is stable per account and consistent across OAuth clients), and is what makes a predecessor→successor migration seamless. Verify the migration preserves `provider_user_id` and user UUIDs.

## G. Audit-trail requirement

Auth is where you most need forensics. The ABSENCE of an append-only auth-event log (login success/failure, new-account, identity-link, session issue/revoke, owner-grant, blocked-login) is itself a MEDIUM finding for any product that bans users or links accounts - a silent takeover is otherwise unreconstructable. Linking events specifically should be auditable and ideally notify the account owner.

## H. Quick exploit-scenario prompts for the auditor

1. Can I log a victim into MY account (login-CSRF) via a missing/again-usable `state`?
2. Can I present a token/profile minted for a different client and have it accepted (audience gap)?
3. Can I link my provider identity onto a victim's account via an email a weak provider "verified"?
4. Does a banned/deleted user regain access by re-running OAuth?
5. Does logout/ban actually kill existing sessions, or just the current one?
6. Where does the freshly minted bearer live - fragment, query, history, localStorage?
7. Is `email_verified` sourced from a validated token or an unauthenticated GET?
