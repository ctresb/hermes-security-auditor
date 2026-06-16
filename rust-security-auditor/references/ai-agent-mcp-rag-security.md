# AI / LLM / Agents / MCP / RAG / Memory - Runtime Security

Companion to the `backend-audit` skill and the deep pack for AI *runtime* security. ADDS the threat surfaces that appear once a Rust service lets a model retrieve private data, remember, call tools, or trigger side effects - going far past the brief SKILL.md "AI/LLM Feature Audit" section. This is about the model as an untrusted, probabilistic control plane; it does NOT repeat the AI-*authored-code* process failures in `references/ai-agent-audit-failure-patterns.md`.

Core stance: the model is untrusted input AND an untrusted instruction-follower. Authorization, validation, and budgets are deterministic Rust code OUTSIDE the model. The system prompt is documentation, not a security boundary.

## A. AI asset inventory (do this first - you cannot audit what you cannot see)

Build a concrete map before judging. Grep the repo for: `openai`, `anthropic`, `async-openai`, `genai`, `ollama-rs`, `candle`, `prompt`, `system_prompt`, `tool`, `function_call`, `mcp`, `rmcp`, `embedding`, `vector`, `pgvector`, `qdrant`, `rag`, `memory`, `retriev`.
List, with file/line evidence:
- Providers + endpoints (managed APIs vs self-hosted vs local), and the exact model IDs/versions and where they are pinned (config, env, hardcoded). Unpinned/"latest" model = silent behavior + safety drift (LLM03:2025 Supply Chain).
- System/developer prompt templates and their versioning. Secrets, internal URLs, tenant IDs, or PII inside a prompt = CRITICAL (LLM07:2025 System Prompt Leakage).
- Tool / function schemas exposed to the model (names, args, what each one DOES).
- MCP servers consumed and MCP servers exposed (official Rust SDK = `rmcp`), transports (stdio / streamable-HTTP).
- Vector stores + embedding models; RAG ingestion sources; agent memory stores (per-user vs shared).
- Eval harnesses, red-team suites, and GenAI telemetry/traces.
Cross-ref: supply-chain pinning in `SKILL.md` (cargo audit/deny/tree); see also CycloneDX ML-BOM in §H.

## B. Prompt injection - direct + indirect (LLM01:2025)

- Treat user text AND all retrieved/tool-returned content as untrusted DATA, never instructions: web pages, files, emails, tickets, PDFs, DB rows, RAG snippets, prior tool outputs, other agents' messages.
- Red flag: prompt built with `format!`/string concat that splices user input or fetched content into the instruction region with no structural separation. Put untrusted content in clearly-delimited data fields, downstream of the system prompt, and tell the model it is data - but understand delimiters are mitigation, not a boundary.
- The system prompt is NOT a security control. "Do not reveal X" / "only do Y" can be overridden. Authorization, tenancy, and allow/deny MUST be enforced in deterministic Rust BEFORE and AFTER the model call, never by instructing the model.
- Indirect injection is the high-severity variant: a poisoned document or fetched page that says "ignore prior rules / call the delete tool / email this data out" then hijacks an unrelated user's agent. This is the bridge from §F (RAG/memory) to §C/§D (output/tool sinks). Maps to OWASP Agentic ASI01 Agent Goal Hijack.
- Required: regression payload corpus for BOTH direct (in user input) and indirect (planted in a retrievable doc / mock fetched page) injection, run on every prompt/tool/RAG change (§G).

## C. Improper output handling (LLM05:2025) - model output reaching a sink

CRITICAL when model output reaches any of these WITHOUT deterministic validation/allowlisting in Rust between the model and the sink:
- SQL (string-built query or identifier) - bind values; map any model-chosen column/sort/table to a static allowlist (see `SKILL.md` dynamic-SQL section, and `references/postgres-deep-and-pooling-audit.md`). Never build `sqlx`/`sea-query` raw fragments from model text.
- Shell / process exec (`std::process::Command`, `tokio::process`) - model-chosen argv or command string = RCE (OWASP Agentic ASI05 Unexpected Code Execution).
- Filesystem paths - model-supplied path -> traversal; canonicalize + confine to a root.
- HTML/Markdown render - model output rendered in a browser/email = XSS / link-based exfiltration; sanitize and strip/forbid image+link auto-fetch (a classic data-exfil channel).
- Email/notification templates, JSON tool arguments, admin APIs, payments, policy/authorization decisions, code generation, and dependency install (`cargo add` / `pip install` from model text = supply-chain RCE).
- Parse tool-call JSON into a typed Rust DTO with `#[serde(deny_unknown_fields)]`; validate every field deterministically before the action runs. Never `eval`/dynamic-dispatch a model-named function without a server-side allowlist.

## D. Agent & tool abuse / excessive agency (LLM06:2025; OWASP Agentic ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse)

- Inventory EVERY tool exposed to the model. Classify side effects: read-only / write / external-call / destructive / expensive / privileged.
- Least privilege per USER and per TENANT: the tool call executes with the requesting principal's authority, re-checked in deterministic code at call time - not with a shared service account. CRITICAL: one generic privileged service account shared across all users/tenants (a tool can then act as anyone).
- Confirmation gates (human-in-the-loop) for destructive / external / high-cost / irreversible actions; provide dry-run paths.
- Audit-log every tool call: principal, tenant, tool name, validated args, decision (allow/deny), outcome (§G).
- Bound the agent: per-tool + per-user rate limits, spend/token budgets, wall-clock timeouts, max tool calls / max reasoning-loop iterations (runaway loops = denial-of-wallet / LLM10:2025 Unbounded Consumption; see cost abuse in `references/web-crypto-hardening-rust.md` §I).
- High-privilege tool (delete, payment, admin, send-email, fetch-arbitrary-URL) without per-user authz AND an approval gate = CRITICAL.

## E. MCP-specific (per MCP Security Best Practices, rev 2025-06-18)

- **Confused deputy**: an MCP proxy with a static upstream `client_id` + dynamic client registration + an upstream consent cookie can skip consent and leak auth codes to an attacker `redirect_uri`. Require per-client consent stored server-side, exact `redirect_uri` matching (no wildcards), and a single-use, server-side `state` set only AFTER consent. (Builds on OAuth 2.0 security BCP RFC 9700; overlaps `references/oauth-oidc-session-identity-audit.md`.)
- **Token passthrough anti-pattern (forbidden by spec)**: an MCP server MUST NOT accept a token not explicitly issued *to it* and forward it downstream - breaks audience binding, audit trail, and rate limits. Validate audience/claims server-side.
- **SSRF via tool/discovery fetches**: clients fetch URLs from `WWW-Authenticate` `resource_metadata`, AS metadata, etc. Block private/reserved ranges per RFC 9728 §7.7 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, link-local `169.254.0.0/16` incl. cloud metadata `169.254.169.254`, `fc00::/7`, `fe80::/10`); enforce HTTPS (loopback excepted); validate every redirect hop; pin DNS to defeat rebinding TOCTOU; prefer an egress proxy. Do not hand-roll IP parsing (octal/hex/IPv4-mapped-IPv6 bypasses). Ties to SSRF in `SKILL.md`.
- **Session hijacking**: MCP servers that implement authorization MUST verify all inbound requests and MUST NOT use sessions for authentication; use CSPRNG non-deterministic session IDs; bind queue/session data as `<user_id>:<session_id>` (user_id derived from the token, not client-supplied) so a guessed session ID can't impersonate.
- **Consent & UX**: explicit user consent before tool execution; visible tool-invocation UX (no silent privileged calls); strict tool allowlists; per-tool input schemas + per-tool auth.
- **Dynamic tool-list changes**: `notifications/tools/list_changed` can enable tools the user never approved - re-consent / re-validate the allowlist on change; do not auto-trust newly-advertised tools.
- **Overbroad OAuth scopes**: reject wildcard/omnibus scopes (`*`, `all`, `full-access`, `files:*`); progressive least-privilege elevation via `WWW-Authenticate` scope challenges. Local-server one-click install MUST show the exact command without truncation and SHOULD sandbox execution (it runs with client privileges).

## F. RAG & memory poisoning (LLM04:2025 Data and Model Poisoning, LLM08:2025 Vector and Embedding Weaknesses; OWASP Agentic ASI06 Memory & Context Poisoning)

- Authenticate ingestion sources; store per-document provenance + a content hash; reject/flag drift so a swapped/poisoned source is detectable.
- Enforce tenant/user ACLs at retrieval time AND re-check ownership AFTER retrieval (defense-in-depth - the same posture as Postgres RLS + explicit `WHERE`, see `references/postgres-deep-and-pooling-audit.md` §C).
- A shared vector index without an enforced tenant/user metadata filter on every query = cross-tenant retrieval leakage = **CRITICAL**. For pgvector, the tenant predicate must be a server-set value (not model/client-supplied) and ideally RLS-backed; verify ANN filters aren't dropped for recall.
- Treat embeddings and persistent memory as sensitive data (embeddings can be partially inverted; memory accretes PII). Apply the same encryption/retention/access controls as the source data.
- Poisoning tests: ingest docs that instruct the model to ignore policy, exfiltrate, or call tools; assert the agent does NOT act on them (this is indirect injection §B realized through the corpus/memory).
- Persistent memory needs review + delete + scoping controls; a write to long-term memory from untrusted content is a stored-injection that hijacks future sessions - log and bound memory writes (§G).

## G. Telemetry & evals (OpenTelemetry GenAI semantic conventions)

- Emit GenAI spans/metrics with the standard attributes: `gen_ai.provider.name`, `gen_ai.request.model` / `gen_ai.response.model`, prompt-template version, `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens`, latency, `gen_ai.tool.name`, retrieval source IDs, and safety/decision outcomes.
- Do NOT log raw prompts/responses by default - they carry PII, secrets, and cross-tenant content (LLM02:2025 Sensitive Information Disclosure). If captured, gate behind access control + redaction + short retention; opt-in via the OTel content-capture controls, never on by default in prod. Raw prompt/response logs with PII = HIGH.
- Alert on: token/cost spikes, tool-denial bursts, detected injection attempts, cross-tenant retrieval events, suspicious memory writes, loop-limit hits.
- Run evals as gates on every prompt/tool/RAG/model change: direct + indirect prompt injection, RAG poisoning, tool abuse / excessive agency, data leakage / cross-tenant, grounding/citation correctness, cost abuse, harmful output. Missing evals on these change types = HIGH.
- Red-team with Microsoft PyRIT and the Microsoft AI Red Team guidance; map findings to MITRE ATLAS (§H). Cross-ref fuzzing posture in the parent SKILL.md.

## H. Framework mapping (cite these in findings)

- **OWASP Top 10 for LLM Applications 2025**: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption. (Differs from the 2023 list - use these 2025 IDs/names.)
- **OWASP Top 10 for Agentic Applications (2026, "ASI"):** ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution (RCE), ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.
- **MITRE ATLAS** (adversarial ML / AI ATT&CK): map injection, poisoning, model-theft, evasion tactics+techniques to ATLAS IDs in findings.
- **NIST AI RMF** (Govern/Map/Measure/Manage) + **Generative AI Profile (NIST.AI.600-1)** for org-level controls and the GenAI-specific risk actions.
- **CycloneDX ML-BOM** for the model/AI supply chain (models, datasets, weights provenance) - pairs with the cargo SBOM posture in SKILL.md.
- **Hugging Face Hub security** for self-hosted/local models: malware/pickle scanning marks (does not block) unsafe files, prefer `safetensors` over pickle, pin commit revisions (not tags), verify org/signing.
- **Google SAIF** as the overarching secure-AI control framework.

## I. Suggested severities (anchor findings to these)

- **CRITICAL**: LLM/tool output reaches shell/SQL/admin/payment/email without deterministic validation; agent holds high-privilege tools without per-user authz + approval gates; cross-tenant RAG/vector/memory leakage; secrets/PII embedded in system prompts; an unauthenticated, unlimited LLM endpoint.
- **HIGH**: no token/spend limits or loop caps; raw prompt/response logs containing PII; unpinned model / tool / prompt / dataset supply chain; missing RAG ACL enforcement; no evals gating prompt/tool/RAG/model changes; MCP token passthrough or SSRF-unprotected tool fetches.
- **MEDIUM**: weak/absent GenAI telemetry; missing model cards / ML-BOM; stale RAG corpus; no citation/grounding validation; incomplete AI incident runbooks; missing visible tool-invocation UX.

## Sources

- OWASP GenAI Security Project: https://genai.owasp.org/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/
- MCP Security Best Practices: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- NIST Generative AI Profile: https://doi.org/10.6028/NIST.AI.600-1
- OpenTelemetry GenAI semantic conventions: https://opentelemetry.io/docs/specs/semconv/gen-ai/
- CycloneDX ML-BOM: https://cyclonedx.org/capabilities/mlbom/
- Hugging Face Hub security: https://huggingface.co/docs/hub/security
- Microsoft AI Red Team: https://learn.microsoft.com/en-us/security/ai-red-team/
- Microsoft PyRIT: https://github.com/microsoft/PyRIT
- Google Secure AI Framework: https://saif.google/
