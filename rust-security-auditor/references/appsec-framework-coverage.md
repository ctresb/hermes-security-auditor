# AppSec Framework Coverage - ASVS / API Top 10 / WSTG / CWE / CAPEC + Coverage Matrix

Companion to the `backend-audit` skill. Where the sibling references teach *what bugs to find*, this pack teaches *how to anchor each finding to an external standard* and how to produce the mandatory Coverage Matrix - so the audit is a defensible, complete sweep, not the author's personal checklist. Cross-references SKILL.md's "Web/API Security in Rust Backends" and the AI/LLM sections.

## A. Frameworks at a glance

**OWASP ASVS 5.0** (Application Security Verification Standard, released May 2025; 17 chapters, ~350 requirements).
- Verification levels: **L1** = streamlined baseline (opportunistic / black-box reachable); **L2** = the default target for most applications handling sensitive data; **L3** = high-assurance (critical systems - L3 scope grew substantially in 5.0 as requirements were re-leveled vs 4.0.3).
- Cite a requirement by its `<chapter>.<section>.<requirement>` number, e.g. `ASVS 5.0 V1.2.x` (V1 = Encoding & Sanitization). Stable chapters to know: Authentication, Authorization/Access Control, Session Management, Self-Contained Tokens, V1 Validation/Sanitization/Encoding, and **V10 OAuth and OIDC** (new in 5.0 - pairs with `references/oauth-oidc-session-identity-audit.md`). ASVS 5.0 RENUMBERED chapters vs 4.0; when unsure of a V-number, cite the chapter NAME + version rather than guessing a number.
- Use ASVS as the *coverage spine*: pick L2, walk the chapters, and any chapter you did not review is a documented gap (see §D).

**OWASP API Security Top 10 - 2023 edition** (cite the exact IDs):
- **API1:2023** Broken Object Level Authorization (BOLA / IDOR-class)
- **API2:2023** Broken Authentication
- **API3:2023** Broken Object Property Level Authorization (mass-assignment + excessive data exposure merged)
- **API4:2023** Unrestricted Resource Consumption
- **API5:2023** Broken Function Level Authorization
- **API6:2023** Unrestricted Access to Sensitive Business Flows
- **API7:2023** Server Side Request Forgery
- **API8:2023** Security Misconfiguration
- **API9:2023** Improper Inventory Management
- **API10:2023** Unsafe Consumption of APIs
- For a Rust gRPC/GraphQL/REST backend this is the single highest-yield list: BOLA (API1) and BFLA (API5) are the modal real findings.

**OWASP WSTG** (Web Security Testing Guide) - a *testing methodology*, not a requirements list. Use its category-prefixed test cases as concrete test ideas: `WSTG-ATHZ-*` (authorization, incl. IDOR/privilege escalation), `WSTG-ATHN-*` (authentication), `WSTG-SESS-*` (session management), `WSTG-INPV-*` (input validation), `WSTG-BUSL-*` (business logic), `WSTG-CONF-*` (configuration & deployment), `WSTG-APIT-*` (API testing, added in v4.2). When you propose a verification test in a finding, name the WSTG case it implements.

**CWE Top 25 / CWE catalog** - the weakness taxonomy you attach to *every* finding. IDs auditors cite constantly (all verified against MITRE):
- **CWE-89** SQL Injection / **CWE-79** Cross-site Scripting
- **CWE-352** Cross-Site Request Forgery (CSRF) / **CWE-918** Server-Side Request Forgery (SSRF)
- **CWE-862** Missing Authorization / **CWE-863** Incorrect Authorization
- **CWE-639** Authorization Bypass Through User-Controlled Key (IDOR) / **CWE-287** Improper Authentication
- **CWE-502** Deserialization of Untrusted Data / **CWE-400** Uncontrolled Resource Consumption
- (`CWE-284` Improper Access Control is the parent of 862/863/639 - use the most specific child that fits.)

**CAPEC** - Common Attack Pattern Enumeration & Classification: the *how-an-attacker-does-it* catalog, complementary to CWE's *what-is-weak*. Attach a CAPEC to the **attacker chain** of a finding to make the exploit concrete (e.g. CAPEC-115 Authentication Bypass, CAPEC-180 Exploiting Incorrectly Configured Access Control Security Levels). CAPEC entries link to the CWEs they exploit - use that linkage to sanity-check your CWE choice. Only add a CAPEC when it sharpens the narrative; do not bolt one on for show (§D).

## B. Mapping rules - every serious finding carries its provenance

A finding rated Medium or above MUST include all of:
- **CWE id** - the most specific weakness (mandatory, always).
- **OWASP mapping** - API Security Top 10 2023 item AND/OR an ASVS 5.0 requirement, when web/API-applicable.
- **CAPEC / attack pattern** - when it sharpens the exploit (optional but encouraged for High/Critical).
- **Affected asset** - exact route/RPC/handler/table (`crate::module::handler`, `POST /v1/orders/{id}`, `orders` table).
- **Exploit preconditions** - what the attacker needs (a valid low-priv session? a second tenant? a guessable id?).
- **Attacker chain** - the concrete step sequence to impact.
- **Verification test/command** - a runnable negative test or `grpcurl`/`curl`/`cargo test` that proves it.

**Worked example - Rust backend IDOR/BOLA:**
> **Finding:** `get_order(order_id)` (tonic service `orders.v1.OrdersService/GetOrder`) loads `SELECT * FROM orders WHERE id = $1` using the path id but never checks the row's `tenant_id`/`owner_id` against the authenticated principal in request extensions.
> **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key); parent CWE-862 (Missing Authorization).
> **OWASP:** API1:2023 BOLA / ASVS 5.0 Access Control chapter (object-level authorization requirement).
> **CAPEC:** CAPEC-180 (Exploiting Incorrectly Configured Access Control Security Levels).
> **Asset:** `orders` table; `OrdersService/GetOrder`. **Preconditions:** any authenticated user + a valid/guessable `order_id` (sequential `i64` makes it trivial; UUIDv4 is still in-scope - IDs are not a security boundary).
> **Chain:** user A authenticates -> calls `GetOrder` with user B's `order_id` -> receives B's order (cross-tenant read; if `UpdateOrder`/`DeleteOrder` share the gap, cross-tenant write/destroy). **Cross-tenant data access is CRITICAL.**
> **Verification (negative test):** create user A and user B with one order each; assert A calling `GetOrder(B.order_id)` returns `PermissionDenied`/`NotFound`, not B's data:
> ```bash
> grpcurl -H "authorization: Bearer $TOKEN_A" -d '{"order_id":"'$ORDER_B'"}' \
>   localhost:50051 orders.v1.OrdersService/GetOrder   # must be denied
> ```
> Encode it as a `cargo test` so it is regression-proof (WSTG-ATHZ-04, IDOR).

Correct pattern: filter ownership in the query (`WHERE id = $1 AND tenant_id = $2`) AND enforce it in code; defense-in-depth with Postgres RLS (see `references/postgres-deep-and-pooling-audit.md` §C). For `async-graphql`, the same gap appears as a resolver loading a node by global id without an owner check - audit every `loader`/`DataLoader` (and see `references/cache-queues-graphql-grpc-security.md` for GraphQL/gRPC-specific authz traps).

## C. The Coverage Matrix (mandatory deliverable)

Reproduce this table in the audit report. Fill **Reviewed?** (Yes / No / Partial / N/A), **Gaps** (specific findings or "none observed"), and **Notes** (scope/why-not + the sibling reference that goes deeper). An honest `No` is a valid, required entry (§D) - it marks negative space, not a failure to do work.

| Area | Framework | Reviewed? | Gaps | Notes |
|------|-----------|-----------|------|-------|
| API object authorization (BOLA/IDOR) | API1:2023 / ASVS Access Control / CWE-639/862 | | | per-route ownership/tenant check; §B worked example |
| Object property auth / mass-assignment | API3:2023 / CWE-915 | | | typed DTOs vs DB models |
| Function-level authorization | API5:2023 / CWE-863 / WSTG-ATHZ | | | role/scope gating on every RPC |
| Auth / session / tokens | API2:2023 / ASVS Auth+Session / CWE-287 | | | see `oauth-oidc-session-identity-audit.md` |
| Resource consumption / DoS | API4:2023 / CWE-400 | | | rate limits, body caps; query-DoS in `postgres-deep-and-pooling-audit.md` |
| Business-flow abuse | API6:2023 | | | anti-automation on costly flows |
| SSRF | API7:2023 / CWE-918 | | | `reqwest` egress allowlist; see `web-crypto-hardening-rust.md` |
| Injection / deserialization | CWE-89/79/502 / ASVS V1 | | | `sqlx` params, `serde` limits |
| Supply chain | NIST SSDF (SP 800-218) / SLSA / CWE-1357 | | | `cargo audit`/`deny`, lockfile, provenance; `supply-chain-ci-cd-security.md` |
| CI/CD pipeline | OWASP CICD-SEC Top 10 | | | secrets, runner trust, artifact integrity; `supply-chain-ci-cd-security.md` |
| Containers / K8s | NIST SP 800-190 / K8s Pod Security Standards (baseline/restricted) | | | non-root, RO rootfs, no privileged; `cloud-container-iac-security.md` |
| AI tools / agents | OWASP LLM06:2025 Excessive Agency / MCP threats | | | tool scoping; AI runtime surface |
| RAG / vector / memory | OWASP LLM08:2025 Vector & Embedding Weaknesses / MITRE ATLAS | | | injection via retrieved/stored context |
| Detection / IR | OWASP Logging Cheat Sheet / NIST SP 800-61 Rev. 3 | | | auth-event audit trail; `detection-privacy-incident-response.md` |

Tailor rows to the actual surface: if there is no container, keep the row but mark Reviewed?=N/A and say why (do not silently drop it). The matrix is the report's table of contents for *coverage*, separate from the findings list.

## D. Discipline rules

- **Do not force irrelevant mappings.** A `serde` recursion-limit gap is CWE-400, not "SQLi-adjacent." A wrong CWE is worse than none - it misleads triage and breaks downstream tooling that consumes CWE IDs. Pick the most specific child weakness, not a vague parent, and not a fashionable-but-wrong label.
- **Explicitly state negative space.** "Container/K8s posture NOT reviewed - service runs on bare ECS, no manifests in repo" is a *required* matrix entry, not an omission. Unmarked silence reads as "reviewed and clean," which is a false assurance. Every `No`/`Partial`/`N/A` needs a one-line why.
- **MITRE ATT&CK only for infra/cloud/credential abuse** (post-exploitation, lateral movement, cred theft, cloud misconfig) - map enterprise/cloud techniques there, NOT application-logic bugs. Don't sprinkle ATT&CK technique IDs on an IDOR.
- **MITRE ATLAS only for AI/ML** adversarial techniques (prompt injection, model/data poisoning, RAG-context manipulation). Pair ATLAS with the OWASP LLM Top 10 (2025) for the AI rows; never apply ATLAS to non-AI code.
- **One finding, one primary CWE.** Note a parent/related CWE in passing if useful, but the finding's identity is its single most-specific CWE.
- **Verify identifiers, never invent them.** If unsure of a CWE number, CAPEC id, ASVS V-number, OWASP API/LLM item, NIST SP number, or K8s field, confirm via the source (WebSearch/WebFetch) - do not guess. A fabricated identifier destroys the report's credibility.

## Sources

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- CWE Top 25: https://cwe.mitre.org/top25/
- CAPEC: https://capec.mitre.org/
