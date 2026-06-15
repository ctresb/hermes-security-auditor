# rust-security-auditor

Hermes Agent skill for deep adversarial audits of Rust backend services.

## Scope

- Axum, Actix Web, Rocket, Warp, Hyper, Tower
- SQLx, Diesel, SeaORM, tokio-postgres, PostgreSQL, RLS, migrations, pools
- OAuth2/OIDC, sessions, JWTs, cookies, CSRF, CORS
- Unsafe Rust, panics, async blocking, DoS, rate limits
- Supply chain, cargo-audit, cargo-deny, build scripts
- AI/LLM features, RAG, tool calls, prompt injection, memory poisoning

## Install

```bash
hermes skills install https://raw.githubusercontent.com/ctresb/hermes-security-auditor/main/rust-security-auditor/SKILL.md
```

## Files

- [`SKILL.md`](./SKILL.md): main Hermes skill.
- [`references/`](./references): deeper playbooks used by the skill.
- [`templates/DEPLOYMENT_GUIDELINES.md`](./templates/DEPLOYMENT_GUIDELINES.md): generic deployment-governance template.
