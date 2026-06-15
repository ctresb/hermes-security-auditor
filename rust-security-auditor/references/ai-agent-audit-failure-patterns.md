# AI Agent Failure Patterns for Backend Audits

Use this reference when auditing repositories likely produced or maintained by AI agents, especially Opus 4.x and GPT-5.x style coding agents.

## Evidence Sources Consulted

- Vectara `awesome-agent-failures`: common agent failures include tool hallucination, response hallucination, goal misinterpretation, plan generation failures, incorrect tool use, verification/termination failures, and prompt injection.
- RepoAudit paper (`arXiv:2501.18160`): repository-level auditing stresses context limits, hallucinated source-sink relations, need for path-sensitive inter-procedural reasoning, and validation loops.
- OpenAI GPT-5.2 prompting guide: long-context work needs explicit re-grounding, restating constraints, quoting/paraphrasing exact details, and scope-drift prevention.
- Production-agent failure writeups: recurring failures include hallucination, prompt injection, inefficient trajectories, poor tool selection, context-window memory degradation, distribution shift, and premature termination.
- Rust By Example `dead_code`: Rust allows suppressing dead-code warnings, but real programs should eliminate dead code.

## Failure Modes to Hunt in Code Reviews

1. Context-loss artifacts
   - Inconsistent naming or architecture across files.
   - Old code path still present after a newer replacement.
   - Duplicate helpers with slightly different semantics.
   - Comments/docs contradict code or each other.
   - README says a route/env/command exists but code does not.

2. Lazy warning suppression
   - `#![allow(dead_code)]`, `#[allow(dead_code)]`, `#[allow(unused)]`, `#[allow(unused_imports)]`, `#[allow(clippy::...)]` without a tight justification.
   - `#[expect(...)]` used broadly or left stale.
   - public APIs made `pub` only to avoid dead-code warnings.
   - test-only helper code leaking into production modules.

3. Premature completion
   - Report or PR claims tests were run but scripts/CI config suggest otherwise.
   - New feature has no negative tests, malformed-input tests, or deployment docs.
   - TODO/FIXME says a security check will be added later.
   - `unimplemented!`, `todo!`, `panic!`, `.unwrap()`, or `.expect()` remain in reachable code.

4. Hallucinated APIs and docs
   - Markdown references env vars, routes, migrations, crates, flags, or scripts absent from the repo.
   - Deployment steps use wrong binary names, wrong Docker service names, wrong ports, or impossible commands.
   - Docs claim PostgreSQL version, UUID version, TLS, or secret rotation policies that code does not enforce.

5. Tool misuse by future agents
   - Deployment docs leave choices open when they should give exact commands.
   - `.env.example` uses weak sample secrets that a future AI might copy to production.
   - Missing `DEPLOYMENT_GUIDELINES.md` or vague deploy instructions.
   - No exact command to generate secrets, migrate DB, run health checks, rollback, or verify TLS.

6. Model-specific audit stance
   - User uses only the selected coding model and the selected coding model. Do not assume either model will remember long context reliably.
   - Force persistent written artifacts: audit folder, exact command logs, explicit scope, exact constraints, and open questions.
   - Check for scope drift, overconfident claims, invented deployment facts, and incomplete verification.

## Auditor Countermeasures

- Re-state hard repo invariants before findings.
- Build a file/route/env/doc map before judging.
- Verify docs against code with searches, not memory.
- Treat every broad `allow` as suspicious until proven scoped and justified.
- Make deployment instructions deterministic enough that another AI can execute them without guessing.
- In final reports, include exact commands run and exact blockers, never inferred success.
