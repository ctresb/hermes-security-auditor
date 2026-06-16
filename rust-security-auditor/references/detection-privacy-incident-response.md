# Detection, Logging, Incident Response, Privacy & Data Lifecycle

Companion to the `backend-audit` skill. Extends SKILL.md "Logging and Observability" + "Data Lifecycle, Audit Logging, and Compliance" and the audit-trail note in `references/oauth-oidc-session-identity-audit.md` §G - adds detection-engineering, incident-response, and privacy depth. A backend is not auditable if the team cannot DETECT abuse, INVESTIGATE it, REVOKE access, RESTORE service, and HONOR user-data expectations. The *absence* of these is itself a finding (§F).

Standards to cite in findings: OWASP A09:2021 (Security Logging and Monitoring Failures), CWE-778 (Insufficient Logging), CWE-223 (Omission of Security-relevant Information), CWE-117 (Improper Output Neutralization for Logs), CWE-532 (Insertion of Sensitive Information into Log File), OWASP API1:2023 (Broken Object Level Authorization, for cross-tenant/IDOR detection), OWASP LLM02/LLM06/LLM08/LLM10:2025 (LLM disclosure / excessive agency / vector-embedding / unbounded consumption), NIST SP 800-61 Rev. 3 (IR, a CSF 2.0 Community Profile), NIST Privacy Framework v1.0.

## A. Security logging - what MUST emit an append-only event

Each event below is a *security* event, distinct from app/request logs (which are noisy and mutable). Missing any of these for the relevant product class is CWE-778 / CWE-223 / OWASP A09:2021.

Required structured, append-only audit events (who, what, target, source IP, correlation ID, server-clock timestamp, outcome):
- Login **success AND failure** (failure carries reason class: bad-cred / unknown-user / locked / banned), logout, MFA/step-up challenge + result.
- **Access denied** (authz failure) - every 403/permission rejection, with the resource and the rule that denied it. Silent denials are uninvestigable.
- **Admin / privileged actions** and **destructive ops** (account/data delete, bulk export, force-logout, impersonation start/stop).
- **Permission / role changes**, group membership, ownership transfer, tenant membership change.
- **Token lifecycle**: create / revoke / rotate / refresh-reuse-detected (for sessions, API keys, PATs).
- **Secret / key events**: key rotation, KMS encrypt/decrypt-for-export, secret read from vault, key-version change.
- **Data export** (per subject, scope, byte/row count) and **account deletion / erasure** (requested -> executed).
- **Payment / billing changes**: plan change, refund, payout, card update, charge dispute.
- **AI tool calls**: tool name, args summary (redacted), allow/deny decision, cost/tokens - without this you cannot detect Excessive Agency abuse (OWASP LLM06:2025); tie to `references/ai-agent-mcp-rag-security.md` and SKILL.md's AI/LLM section.
- **Webhook** delivery failures, retries, signature-verification failures (in + out).

Correct pattern:
- Append-only sink (separate table / WORM bucket / SIEM); app DB rows are not an audit trail if the same service can `UPDATE`/`DELETE` them. Separate write path, restricted grants, integrity (hash-chain or external store).
- A `revoke_all_for_user` / `ban` path that exists but emits no event is half-built - flag it (cross-ref `oauth-oidc-session-identity-audit.md` §D, §E).

## B. Log safety - redaction, injection, integrity (Rust framing)

Red flags:
- **Sensitive data in logs** (CWE-532): tokens, cookies, `Authorization`, passwords, API keys, OAuth `code`/`state`/`refresh_token`, `id_token`, DB URLs (creds in DSN), full PAN, PII. Includes `TraceLayer` defaults logging headers/query strings (SKILL.md "Tower Middleware, CORS, and Security Headers"; `web-crypto-hardening-rust.md` §A).
- **Log injection** (CWE-117): user-controlled fields (username, UA, path, header values) written into log lines without neutralizing `\n`/`\r`/control chars -> forged log entries, broken parsers, ANSI-escape terminal injection. Strip/encode CR/LF and C0 controls in every user field; prefer structured key/value fields over string interpolation so the encoder escapes them.
- **`#[derive(Debug)]` on secret-bearing structs** prints them via `{:?}` in error/trace lines. Require redacted manual `Debug`, `secrecy::Secret<T>`, or `zeroize` - cross-ref `web-crypto-hardening-rust.md` §F. Verify secrets never appear in `Display`/panic messages either.
- **Raw prompt/response logging** for LLM flows captures injected payloads and user PII in plaintext (OWASP LLM02:2025 Sensitive Information Disclosure) - only behind access control + retention limits; redact before persisting (ties to §A AI events).
- Verbose error -> client: SQL, stack traces, internal IDs leak to the response body (SKILL.md "Logging and Observability"). Separate internal error from safe public error.

Correct pattern (Rust):
- `tracing` with a redacting layer/formatter; allowlist which fields are logged rather than denylist. Custom `tracing_subscriber` layer that drops/masks known-sensitive keys; never log whole request/response structs.
- **Correlation/request IDs** (`tower-http` `RequestId` / `tracing` span) propagated across services and into audit events so an incident is reconstructable - without using a guessable sensitive object ID as the correlation key.
- **Synchronized clocks** (NTP/chrony on every host) and a single timezone (UTC) - unsynced clocks make multi-host timelines and §A event ordering useless for forensics.

## C. Detection / alerting - each alert ties to a §A event

An audit event nobody alerts on is necessary but insufficient (OWASP A09:2021 calls out "not monitored"). For each, name the source event and a threshold/anomaly rule:
- **Brute force / credential stuffing** -> login-failure spike per IP / per account / global; distributed low-and-slow over many accounts.
- **Password-reset / email-verification abuse** -> reset-request rate per account/IP; many resets, no completion.
- **IDOR / BOLA attempts** (OWASP API1:2023 Broken Object Level Authorization) -> burst of authz-denied (§A access-denied) on enumerable IDs by one principal; **cross-tenant access is CRITICAL** - any tenant-mismatch denial should page (cross-ref `postgres-deep-and-pooling-audit.md` RLS).
- **SSRF blocks** -> outbound-fetch denials to internal/metadata ranges (link-local `169.254.169.254`, RFC1918) - see SKILL.md SSRF controls.
- **Token / session anomalies** -> issuance spikes, refresh-token reuse detected (theft signal), impossible-travel, sudden API-key call-rate jump.
- **LLM cost / tool spikes** -> tokens-per-user or $/min over budget (OWASP LLM10:2025 Unbounded Consumption / denial-of-wallet); tool-call **denial** rate (probing for over-permissioned tools, OWASP LLM06:2025); cross-tenant retrieval attempts in RAG (OWASP LLM08:2025 Vector and Embedding Weaknesses - CRITICAL).
- **IAM / KMS changes** -> any IAM policy edit, key rotation outside change window, new admin grant - high severity by default.
- **Queue retry storms** -> DLQ growth, retry-rate spike (cost + cascading failure); cache-poisoning indicators (anomalous cache-key churn, surge of `Vary`-sensitive misses - cross-ref `web-crypto-hardening-rust.md` §B CORS/`Vary`).

Correct pattern: alerts route to on-call (§D) with severity; the costliest/most-abusable flows (login, reset, export, payments, AI) MUST have at least one live detection. No detection on those = a finding.

## D. Incident response (NIST SP 800-61 Rev. 3)

Rev. 3 reframes IR as a CSF 2.0 Community Profile across Govern / Identify / Protect / Detect / Respond / Recover rather than the old four-phase lifecycle - assess capability, not paperwork.

Required checks:
- **Runbooks exist** for the realistic top incidents: credential/key compromise, data breach, account-takeover wave, ransomware/destructive action, dependency CVE / supply-chain (cross-ref SKILL.md `cargo audit/deny`), DoS/denial-of-wallet.
- **On-call ownership**: a named, reachable owner per service; escalation path; alerts (§C) actually page someone.
- **Fast credential/key rotation**: can compromised DB creds, signing keys, OAuth client secrets, API keys, and webhook secrets be rotated *quickly without downtime* - requires dual-key verify windows and `kid` (cross-ref `web-crypto-hardening-rust.md` §F). No rotation runbook is a finding for any service holding secrets.
- **Backups exist AND restore is tested**: an untested backup is not a backup. Verify a documented, exercised restore.
- **RTO** (max tolerable downtime) and **RPO** (max tolerable data loss) defined and met by the backup cadence + restore drill. PITR for Postgres (WAL archiving) maps RPO to seconds/minutes; nightly-dump-only often violates a stated RPO - flag the gap.
- **Evidence preservation**: append-only audit log (§A) + log retention long enough to investigate (breaches are found months later); snapshot/quarantine before remediation overwrites evidence.

## E. Privacy & data lifecycle (NIST Privacy Framework v1.0)

Functions: Identify-P / Govern-P / Control-P / Communicate-P / Protect-P (data minimization is a Control-P practice). Audit against capability, not policy prose.

Required user-facing data rights:
- **Account deletion** and **data export**: real, reachable paths - not just a docs claim (an AI-authored repo often documents `/account` delete that no route serves; cross-ref `ai-agent-audit-failure-patterns.md`). Deletion must cascade or tombstone all PII, not just the user row; export must be scoped to the requesting subject (an export that leaks other users' rows is CRITICAL).
- **Right-to-erasure** where applicable (GDPR Art.17 / CCPA): erasure propagates to replicas, backups policy, search indexes, caches, logs, and 3rd-party processors; "soft delete only" that retains PII indefinitely is an erasure gap.
- **Provider unlink while preserving >=1 login method**: unlinking the last identity must be refused or the account becomes unrecoverable / orphaned (cross-ref `oauth-oidc-session-identity-audit.md` §F).
- **Session list + self-revoke**: user can see active sessions/devices and revoke them; revoke must actually invalidate server-side (cross-ref `oauth-oidc-session-identity-audit.md` §D).
- **Reaper / TTL sweep** for expired tokens, single-use OAuth exchange codes, password-reset tokens, and stale sessions. Absence = unbounded table growth (DoS, cross-ref `postgres-deep-and-pooling-audit.md`) AND a longer leak/replay window. A `getrandom`-strong token left forever is still a standing liability.
- **PII retention + minimization** (Control-P): collect only what's needed, define retention per data class, auto-purge past retention. Logs/analytics quietly retaining PII forever violate minimization. Destructive `DELETE /account` with no re-auth/confirmation/audit event is itself a finding.

## F. Negative-space framing - absence is the finding

For any product that handles **auth, money, tenants, or AI**, the *absence* of these capabilities is a reportable finding even with zero exploit demonstrated. State severity explicitly:
- No append-only audit trail (§A) -> MEDIUM baseline; HIGH if it bans users, links accounts, moves money, or runs AI tool calls (incidents are unreconstructable - CWE-778, OWASP A09:2021).
- No detection/alert on a costly or abusable flow (login, reset, export, payments, AI cost/tool-denial) -> MEDIUM-HIGH (§C). Cross-tenant retrieval/access with no alert -> CRITICAL.
- No IR runbook / no tested restore / no defined RTO+RPO / no fast key-rotation path -> MEDIUM-HIGH (§D); a service holding signing keys with no rotation runbook is HIGH.
- No deletion or export path, no last-method unlink guard, no session self-revoke -> MEDIUM, rising to HIGH where erasure is legally required.
- No reaper for expired tokens/codes/sessions -> MEDIUM (growth + widened leak window).
- Always state it is a negative-space / defense-in-depth finding and why it matters for *this* product class, per the auditor stance in SKILL.md ("What logs/alerts would or would not detect it?").

## Sources

- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST Incident Response SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST Privacy Framework: https://www.nist.gov/privacy-framework
- OWASP API Security Top 10 2023 (API1:2023 BOLA): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
