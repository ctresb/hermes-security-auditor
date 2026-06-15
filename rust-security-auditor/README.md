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
- Unsafe Rust, panics, async blocking, DoS, rate limits
- Supply chain, cargo-audit, cargo-deny, build scripts
- AI/LLM features, RAG, tool calls, prompt injection, memory poisoning

## Output

A serious audit should include:

- attack surface map;
- ranked findings;
- affected code paths;
- attacker chain;
- remediation;
- verification steps;
- dependency, database, auth, crypto, deployment, and AI/LLM review sections.

## Files

- [`SKILL.md`](./SKILL.md): main Hermes skill.
- [`references/`](./references): deeper playbooks used by the skill.
- [`templates/DEPLOYMENT_GUIDELINES.md`](./templates/DEPLOYMENT_GUIDELINES.md): generic deployment-governance template.
