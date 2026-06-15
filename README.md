<p align="center">
  <img src="logo.svg" alt="Hermes Security Auditor" width="100%">
</p>

# Hermes Security Auditor

<p align="center">
  <a href="https://hermes-agent.nousresearch.com/docs/user-guide/features/skills"><img src="https://img.shields.io/badge/Hermes-Skill-FF0073?style=for-the-badge" alt="Hermes skill"></a>
  <a href="./rust-security-auditor/SKILL.md"><img src="https://img.shields.io/badge/Auditor-Rust-orange?style=for-the-badge&logo=rust&logoColor=white" alt="Rust auditor"></a>
  <a href="https://skills.sh/ctresb/hermes-security-auditor/rust-security-auditor"><img src="https://img.shields.io/badge/skills.sh-rust--security--auditor-black?style=for-the-badge" alt="skills.sh listing"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT"></a>
</p>

Adversarial security-audit skills for [Hermes Agent](https://github.com/NousResearch/hermes-agent). The current package is a Rust backend auditor that helps Hermes review real code paths, attack chains, database behavior, deployment defaults, and AI/LLM risk without turning the audit into a generic checklist.

This repository is for reusable auditor skills. Each auditor lives in its own directory so contributors can improve Rust now and add Go, Python, Node, or other stacks later.

---

## Quick install

Install the Rust auditor into Hermes:

```bash
hermes skills install ctresb/hermes-security-auditor/rust-security-auditor
```

Start Hermes with the skill loaded:

```bash
hermes -s rust-security-auditor
```

Or load it inside an existing Hermes conversation:

```text
/rust-security-auditor
```

Then ask Hermes to audit a Rust backend repository and write the report into the target repo.

```text
Audit this Rust backend with rust-security-auditor. Create a timestamped audit directory, verify what you can run locally, rank findings by exploitability, and include remediation plus verification steps.
```

---

## Included auditors

| Auditor | Status | Scope |
|---|---|---|
| [`rust-security-auditor`](./rust-security-auditor/SKILL.md) | active | Rust web backends, async runtimes, PostgreSQL, OAuth/OIDC, sessions, RLS, migrations, supply chain, crypto, deployment defaults, AI/LLM risks |
| `go-security-auditor` | planned | Go backend security audits |

---

## What the Rust auditor does

<table>
<tr><td><b>Maps the system first</b></td><td>Workspace shape, web framework, database layer, auth/session stack, background jobs, external integrations, and trust boundaries.</td></tr>
<tr><td><b>Hunts exploit chains</b></td><td>Looks for how small issues combine into auth bypass, data theft, privilege escalation, denial of service, persistence, cost abuse, or destructive database actions.</td></tr>
<tr><td><b>Audits Rust-specific failure modes</b></td><td>Unsafe boundaries, panic-driven DoS, blocking work inside async runtimes, dependency risk, warning suppression, dead code, and AI-generated cruft.</td></tr>
<tr><td><b>Goes deep on PostgreSQL</b></td><td>SQL injection beyond simple value binding, transaction races, RLS gaps, migrations, pool exhaustion, privilege boundaries, TLS, and version or identifier policy drift.</td></tr>
<tr><td><b>Reviews web and identity controls</b></td><td>OAuth/OIDC, JWTs, sessions, cookies, CSRF, CORS, SSRF, webhooks, uploads, path handling, command execution, logs, and middleware order.</td></tr>
<tr><td><b>Covers AI/LLM features</b></td><td>Prompt injection, RAG poisoning, tool-call abuse, memory poisoning, unsafe output handling, excessive agency, and stored-data exfiltration paths.</td></tr>
<tr><td><b>Requires evidence</b></td><td>Findings must include affected code paths, attacker chain, impact, remediation, and a concrete way to verify the fix.</td></tr>
</table>

---

## Output contract

The auditor is meant to produce a serious report, not quick comments. A complete audit should include:

- attack surface map;
- ranked findings with severity and confidence;
- affected file paths and code evidence;
- attacker chain and exploitability reasoning;
- remediation steps;
- verification commands or tests;
- positive security notes where useful;
- dependency, database, auth, crypto, deployment, and AI/LLM review sections;
- remediation roadmap split into fix now, fix next, and monitor.

By default the skill asks Hermes to create a timestamped audit directory in the target backend, for example:

```text
audit_DD-MM-AAAA-HH-MM/
  RUST_BACKEND_SECURITY_AUDIT.md
```

---

## Repository layout

```text
hermes-security-auditor/
  logo.svg
  README.md
  docs/
    audit-methodology.md
    contributing.md
  rust-security-auditor/
    README.md
    SKILL.md
    references/
      ai-agent-audit-failure-patterns.md
      oauth-oidc-session-identity-audit.md
      postgres-deep-and-pooling-audit.md
      rust-backend-audit-patterns.md
      web-crypto-hardening-rust.md
    templates/
      DEPLOYMENT_GUIDELINES.md
  scripts/
    validate_skills.py
```

---

## Docs

| Document | Purpose |
|---|---|
| [`docs/audit-methodology.md`](./docs/audit-methodology.md) | Short version of the review loop used by the auditor. |
| [`docs/contributing.md`](./docs/contributing.md) | Contribution quality bar for new checks and reference notes. |
| [`rust-security-auditor/README.md`](./rust-security-auditor/README.md) | Skill-specific install notes and file map. |
| [`rust-security-auditor/templates/DEPLOYMENT_GUIDELINES.md`](./rust-security-auditor/templates/DEPLOYMENT_GUIDELINES.md) | Generic deployment-governance template for audited projects. |

---

## Validate changes

Run the local validator before opening a PR:

```bash
python scripts/validate_skills.py
```

For install packaging, test the full GitHub identifier form in an isolated Hermes home:

```bash
TMP_HOME=$(mktemp -d "$HOME/.hermes-install-test.XXXXXX")
HERMES_HOME="$TMP_HOME" hermes skills install ctresb/hermes-security-auditor/rust-security-auditor --yes
rm -rf "$TMP_HOME"
```

The identifier form matters because it installs the whole skill directory, including `references/` and `templates/`. A raw `SKILL.md` URL only installs the main markdown file.

---

## Contributing

Good contributions improve audit quality. Prefer concrete vulnerability classes, stronger verification workflows, clearer severity guidance, better Rust/PostgreSQL/OAuth examples, or reduced false positives.

Before adding a check, make sure it can answer:

1. Who can reach it?
2. What input does the attacker control?
3. What guard exists and why does it fail?
4. What is the immediate impact?
5. What second step or chain does it unlock?
6. How can maintainers verify the fix?

See [`docs/contributing.md`](./docs/contributing.md) for the full bar.

---

## Roadmap

- Keep improving `rust-security-auditor` with real audit lessons.
- Add stack-specific auditors only when they can be deeper than a generic checklist.
- Keep project-specific policy checks configurable. Do not hardcode private defaults as public rules.

---

## License

MIT. See [`LICENSE`](./LICENSE).
