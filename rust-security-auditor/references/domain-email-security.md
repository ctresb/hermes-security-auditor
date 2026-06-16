# Domain, DNS & Email Security

Companion to the `backend-audit` skill. Adds the domain-name, DNS, and email surfaces that sit beside a Rust backend but rarely appear in code review: sender authentication (SPF/DKIM/DMARC), transport security (MTA-STS/TLS-RPT), DNS hygiene (DNSSEC/CAA), takeover classes (subdomain/dangling/wildcard/custom-domain), CDN origin leakage, host/forwarded-header trust, and the email-driven auth flows (reset, magic link, invite) that turn a DNS or header bug into account takeover. Activate when the repo references domains, DNS, email send, password reset / magic links, custom domains, or inbound email/webhook parsing. For OAuth/magic-link token mechanics see `references/oauth-oidc-session-identity-audit.md`; for host/forwarded-header trust in middleware see `references/web-crypto-hardening-rust.md`; for send/reset rate-limit alerting see `references/detection-privacy-incident-response.md`.

## A. Sender authentication: SPF, DKIM, DMARC

Email is unauthenticated by default; without all three an attacker spoofs your domain to phish your users (and to forge the "reset your password" mail itself).
- **SPF** (TXT `v=spf1 ...`): authorizes sending IPs. Red flags: no SPF record; `+all` (allow-any, worthless); `?all`/`~all` left as the only control; more than 10 DNS-lookup mechanisms (SPF permerror -> silent fail-open); multiple SPF records on one domain (invalid). Correct: explicit includes for real senders ending in `-all` (hardfail) once DMARC is enforced.
- **DKIM** (TXT at `selector._domainkey`): cryptographic signature over headers/body. Red flags: no DKIM; key < 2048-bit RSA; a test/`t=y` flag left in prod; a stale selector whose private key has leaked/rotated but the public key lingers. Each active sending service needs its own selector.
- **DMARC** (TXT at `_dmarc`): ties SPF/DKIM to the visible `From:` via alignment and sets policy. Red flags: no DMARC; `p=none` treated as protection (it is monitor-only); no `rua` aggregate-report address (you are blind to abuse); `sp=` weaker than `p=`; `pct<100` left indefinitely. Target: `p=quarantine` -> `p=reject` with alignment, after `rua` shows legitimate mail passes.
- Maps to CWE-290 (Authentication Bypass by Spoofing). A weak/absent DMARC on a product that sends auth email is a finding because it directly enables credible reset/invite phishing.

## B. Transport & brand: MTA-STS, TLS-RPT, BIMI

- **MTA-STS** (`_mta-sts` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt`, `mode=enforce`): forces TLS for inbound SMTP and pins MX hosts, blocking STARTTLS-stripping downgrade MITM. Red flags: `mode=testing`/`none` in prod; policy file unreachable; MX names in the policy not matching DNS.
- **TLS-RPT** (`_smtp._tls` TXT `v=TLSRPTv1; rua=...`): reports TLS/MTA-STS failures so downgrade attempts are visible. Absence is a detection gap, not a direct break.
- **BIMI** (`default._bimi` TXT): brand logo + optionally a VMC; requires `p=quarantine`/`reject` DMARC first. Anti-impersonation hardening, not a control by itself; cite as defense-in-depth.

## C. DNS hygiene: DNSSEC, CAA, MX posture

- **DNSSEC**: signs DNS responses against cache-poisoning/spoofing of your records (including the SPF/DKIM/DMARC/MTA-STS TXTs above and the A/CNAME an attacker would redirect). Flag unsigned zones for high-value domains; verify the DS record is published at the registrar (a signed zone with no DS chain is unvalidated). DNSSEC misconfig can also hard-fail resolution - check, do not assume.
- **CAA** (`issue`/`issuewild`/`iodef`): restricts which CAs may issue certs for the domain, limiting mis-issuance after a domain/DNS compromise. Red flags: no CAA; overly broad `issue` allowing any CA; no `iodef` contact. Include `issuewild ";"` if no wildcard certs are intended.
- **MX / open relay**: the mail host must not be an open relay; SMTP AUTH required for submission; inbound restricted to MTA-STS-enforced TLS. Stale MX pointing at a decommissioned provider is a takeover vector (see §D).

## D. Takeover classes: subdomain, dangling DNS, wildcard, custom domains

The highest-severity DNS findings. A taken-over subdomain under your apex inherits cookie scope, CORS trust, OAuth `redirect_uri` allowlists, and email-link trust -> often CRITICAL.
- **Subdomain takeover**: a `CNAME`/`ALIAS` pointing at a deprovisioned third-party (S3/CloudFront/GitHub Pages/Heroku/Azure/Fastly/Netlify/Zendesk, etc.) that an attacker can re-register and serve content from your subdomain. Inventory every `CNAME` to an external service; verify each target is still claimed. The classic fingerprint is the provider's "no such bucket/app" page.
- **Dangling DNS**: an `A`/`AAAA` to a released cloud IP an attacker can re-allocate (elastic IP churn), or a record for a torn-down service. Flag records resolving to IPs/hosts you no longer control; reconcile DNS against live infra (IaC drift - cross-ref `references/cloud-container-iac-security.md`).
- **Wildcard DNS** (`*.<domain>`): every label resolves, so any user-chosen subdomain (tenant slugs, preview envs) is live - expands cookie/CORS/CSRF and phishing surface, and can mask a takeover. If used, scope cookies to the exact host (never `Domain=.apex`), and never reflect the arbitrary `Host` into trust decisions (§E).
- **Tenant custom-domain takeover**: products that let tenants map `app.theirbrand.com` must (1) require a per-tenant DNS verification token (TXT/CNAME) before serving, (2) RE-verify before (re)issuing the TLS cert and periodically after, and (3) release the mapping when the tenant's DNS stops pointing at you. Bugs: ownership proven once and never re-checked (tenant drops the domain, attacker re-points it and inherits the tenant's app/session/cookies); shared cookie/session scope across custom domains; ACME `http-01` issuance on an unverified inbound `Host`. CRITICAL when a custom domain inherits another tenant's data or session.
- **Domain verification takeover**: any "prove you own this domain/email" flow (email allow-listing, SSO domain claim, custom domain) keyed on a guessable/reusable/non-expiring token, or that auto-grants org membership by email domain (`@victim.com`) without verifying the *specific* claimant, lets an attacker claim a domain/org. Tokens must be single-use, high-entropy, expiring, and bound to the requesting principal.

## E. CDN origin leakage & host/forwarded-header trust

- **Origin IP leakage behind a CDN/WAF**: if the origin's real IP is discoverable (historical DNS, leaking it in email `Received:` headers, SSRF, a `dev`/`direct` subdomain `A` record, TLS SAN/cert transparency, default vhost), an attacker bypasses the CDN/WAF and hits the origin directly. Mitigation to verify: origin firewall accepts traffic ONLY from the CDN's published ranges (or via an authenticated origin pull / mTLS header), not `0.0.0.0/0` (cross-ref `references/cloud-container-iac-security.md` IaC ingress).
- **Host / forwarded-header trust** (CWE-644 improper handling of headers; password-reset poisoning): building absolute URLs, reset/magic-link emails, redirects, or cache keys from inbound `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto` / `X-Original-URL` lets an attacker send a victim a "reset" link pointing at attacker-controlled host -> token theft on click. Correct: build all outbound links from a configured canonical base URL, never from the request; only trust forwarded headers when the immediate peer is a configured trusted proxy (cross-ref `references/web-crypto-hardening-rust.md` and the spoofable-proxy-header chain in `references/rust-backend-audit-patterns.md`); validate `Host` against an allowlist and return a fixed default otherwise. Web-cache-poisoning angle: see `references/cache-queues-graphql-grpc-security.md` §A.

## F. Email-driven auth flow abuse (reset / magic link / invite / verification)

These flows are the bridge from DNS/header bugs to account takeover; they also gate cost-abuse.
- **Link host integrity**: reset/magic-link/verify URLs MUST use the canonical base URL, not request headers (§E). A host-poisoned link is account takeover, not a UX bug.
- **Token hygiene** (cross-ref `references/oauth-oidc-session-identity-audit.md`): single-use, high-entropy (`getrandom`/`OsRng`, >=128 bit), short TTL, hashed at rest, invalidated on use AND on password change, not reflected in logs/Referer/redirects. A magic link is a bearer credential - same rules as a session token.
- **Enumeration**: reset/login/verify/invite responses and timings must not reveal whether an account exists (uniform response + constant-ish time). Maps to CWE-204 / OWASP WSTG-IDNT/ATHN.
- **Open redirect on post-action bounce** (CWE-601): the `next`/`returnTo`/`redirect` after login/verify must be an allowlisted relative path or exact host - never an arbitrary absolute URL, which exfiltrates the freshly minted session/token.
- **Inbound email/webhook parsing** (treat as untrusted input, cross-ref `references/cache-queues-graphql-grpc-security.md` consumer-boundary stance): verify provider webhook signatures over the RAW body, constant-time (SES/SendGrid/Postmark/Mailgun; see `references/web-crypto-hardening-rust.md` inbound-webhook section); the `From:`/envelope is spoofable - authenticate via SPF/DKIM/DMARC pass flags from the provider, never trust display `From`; parse MIME/attachments with size + nesting + content-type limits (decompression/zip bombs, see deserialization limits); strip/neutralize HTML; never auto-execute or auto-fetch links/images from inbound mail.

## G. Rate limits & denial-of-wallet for email flows

Every user-triggerable email is a cost + abuse vector (SMS/push too). Cross-ref `SKILL.md` "Rate Limiting at Scale and Denial-of-Wallet" and OWASP API6:2023.
- Per-account AND per-IP AND global caps on: password reset, email verification resend, magic-link request, invites, "contact" / notification sends. Unbounded = mailbomb (harassment + provider reputation/blacklisting) and a billing-drain.
- Invites: cap per user/tenant; a tenant cannot blast unlimited invite mail (spam relay through your reputation).
- Tie limits to detection (reset-abuse / send-spike alerts in `references/detection-privacy-incident-response.md` §C). Confirm limits are shared-store backed, not per-instance in-memory (bypassed by horizontal scaling - cross-ref `references/rust-backend-audit-patterns.md`).

## Security checks (quick auditor pass)

- Resolve and grade SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI/CAA/DNSSEC for every sending and product domain; flag `p=none`, `+all`, missing DKIM, absent DMARC.
- Inventory every `CNAME`/`A` to a third party and confirm the target is still owned (subdomain/dangling takeover sweep).
- Confirm reset/magic-link/verify URLs derive from a configured canonical base, not `Host`/`X-Forwarded-*`.
- Confirm tenant custom-domain flows re-verify ownership before cert issuance and on a schedule, and isolate cookie/session scope per domain.
- Confirm origin IP is not CDN-bypassable and origin ingress is locked to CDN ranges / authenticated pull.
- Confirm per-account/IP/global rate limits + enumeration resistance on every email-trigger flow; verify inbound mail/webhook signature + MIME limits.

## High-value search patterns

```bash
rg -n "X-Forwarded-Host|X-Forwarded-Proto|X-Original-URL|X-Rewrite-URL|req.headers.*host|HOST\b" --type rust
rg -n "reset_url|magic_link|verify_url|confirmation_url|base_url|APP_URL|PUBLIC_URL|callback_url|returnTo|redirect_to|next=" --type rust
rg -n "spf|dkim|dmarc|mta-sts|dnssec|\bCAA\b|_domainkey|_dmarc" -i
rg -n "custom_domain|verify_domain|domain_token|cname|verification_token|acme|http-01|dns-01" -i --type rust
rg -n "send_email|send_mail|lettre|sendgrid|mailgun|ses|postmark|smtp|invite" -i --type rust
rg -n "format!\(.*https?://.*\{" --type rust   # URLs built by interpolation (host-poisoning candidates)
```

## Sources

- RFC 7208 (SPF): https://www.rfc-editor.org/rfc/rfc7208
- RFC 6376 (DKIM): https://www.rfc-editor.org/rfc/rfc6376
- RFC 7489 (DMARC): https://www.rfc-editor.org/rfc/rfc7489
- RFC 8461 (MTA-STS): https://www.rfc-editor.org/rfc/rfc8461
- RFC 8460 (TLS-RPT): https://www.rfc-editor.org/rfc/rfc8460
- RFC 8659 (CAA): https://www.rfc-editor.org/rfc/rfc8659
- RFC 9364 / DNSSEC (BCP 237): https://www.rfc-editor.org/rfc/rfc9364
- BIMI (AuthIndicators Working Group): https://bimigroup.org/
- OWASP Web Security Testing Guide (host header, identity, authentication): https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger - Host header attacks (password-reset poisoning): https://portswigger.net/web-security/host-header
- CWE-290 Authentication Bypass by Spoofing: https://cwe.mitre.org/data/definitions/290.html
- CWE-601 Open Redirect: https://cwe.mitre.org/data/definitions/601.html
