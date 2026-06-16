# rust-security-auditor

Hermes Agent skill for deep adversarial audits of Rust backend services.

## Install

Install the full skill directory, including `references/` and `templates/`:

```bash
hermes skills install ctresb/hermes-security-auditor/rust-security-auditor
```

Use the skill from a fresh Hermes session:

```bash
hermes -s rust-security-auditor
```

Or load it inside an existing Hermes conversation:

```text
/rust-security-auditor
```

## Scope

- Axum, Actix Web, Rocket, Warp, Hyper, Tower
- SQLx, Diesel, SeaORM, tokio-postgres, PostgreSQL, RLS, migrations, pools
- OAuth2/OIDC, sessions, JWTs, cookies, CSRF, CORS
- Unsafe Rust, panics, async blocking, DoS, rate limits; fuzzing/Miri/sanitizers/Loom tooling
- Supply chain, cargo-audit/deny/vet/geiger, build scripts; CI/CD (GitHub Actions), SBOM, SLSA, provenance
- Containers/Kubernetes/IaC (Docker, PSS, Terraform, IAM/KMS)
- Caches/CDN, queues/streams, GraphQL (`async-graphql`/`juniper`), gRPC (`tonic`)
- Domain/DNS/email: SPF/DKIM/DMARC, subdomain/custom-domain takeover, reset/magic-link abuse
- AI/LLM/agent features: RAG, MCP, tool calls, prompt injection, memory poisoning, evals/telemetry
- Detection, logging, incident response, privacy and data lifecycle
- Business-logic abuse; external-standard coverage matrix (OWASP/CWE/NIST/SLSA/K8s PSS)

Surface-specific areas are only reviewed when the matching surface is present in the repository.

## Output

A serious audit should include:

- attack surface map;
- a coverage matrix mapping reviewed areas to external standards (with gaps marked);
- ranked findings with severity and confidence;
- affected code paths;
- attacker chain;
- remediation;
- verification steps;
- per-surface review sections: dependency/CI-CD, database, auth, crypto, web/middleware, cloud-container-IaC, cache/queue/GraphQL/gRPC, domain/email, AI/LLM, and detection/IR (those tied to a surface only when present).

## Files

- [`SKILL.md`](./SKILL.md): main Hermes skill.
- [`references/`](./references): deeper, surface-triggered playbooks used by the skill (frameworks/coverage, Rust unsafe+fuzzing, supply-chain/CI-CD, cloud/container/IaC, cache/queue/GraphQL/gRPC, AI/MCP/RAG, detection/IR/privacy, domain/email, plus the original auth/postgres/web-crypto/patterns packs).
- [`templates/DEPLOYMENT_GUIDELINES.md`](./templates/DEPLOYMENT_GUIDELINES.md): generic deployment-governance template.
