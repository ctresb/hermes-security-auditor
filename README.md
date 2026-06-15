# Hermes Security Auditor

Reusable Hermes Agent skills for adversarial security audits.

Current focus: Rust backend security.

## Skills

| Skill | Status | Scope |
|---|---|---|
| [`rust-security-auditor`](./rust-security-auditor/SKILL.md) | active | Rust web backends, async runtimes, PostgreSQL, OAuth/OIDC, sessions, RLS, migrations, supply chain, crypto, AI/LLM risks |
| `go-security-auditor` | planned | Go backend security audits |

## Install

Full install from GitHub, including `references/` and `templates/`:

```bash
hermes skills install ctresb/hermes-security-auditor/rust-security-auditor
```

Optional: add this repo as a tap for discovery:

```bash
hermes skills tap add ctresb/hermes-security-auditor
```

## Use

```bash
hermes -s rust-security-auditor
```

Then ask Hermes to audit a Rust backend repository.

## Repository layout

```txt
rust-security-auditor/
  SKILL.md
  references/
  templates/
docs/
scripts/
```

## Design goals

- Findings must include attacker chain, evidence, remediation, and verification.
- Prefer dynamic verification over static-only review when the project can run locally.
- Keep project-specific policy checks configurable. Do not force private defaults such as a specific UUID version or PostgreSQL major unless the target repository documents them.
- Treat AI-authored code and docs as potentially stale, incomplete, or hallucinated until verified.

## License

MIT.
