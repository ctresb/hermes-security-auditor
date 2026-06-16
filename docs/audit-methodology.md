# Audit Methodology

The Rust security auditor uses an adversarial review loop:

1. Map attack surface and trust boundaries.
2. Detect repository surfaces (CI/CD, containers/IaC, caches/queues, GraphQL/gRPC, AI/MCP/RAG, domain/email) and load the matching reference packs.
3. Run safe mechanical checks.
4. Review code paths manually, always-on core plus the activated surface modules.
5. Generate candidate findings.
6. Try to refute each finding end-to-end.
7. Dynamically verify migrations/tests when feasible.
8. Rank findings by severity and confidence.
9. Map reviewed areas and findings to external standards in a coverage matrix; record unreviewed-but-present surfaces as negative-space gaps.
10. Write remediation and verification steps.

Surface-triggered modules keep the audit focused: a pack is only loaded when its surface exists in the repo. The coverage matrix makes blind spots explicit instead of silent.

Static review is not enough for database-backed systems. Race conditions, migrations, RLS gaps, pool state bleed, and conflict paths often appear only under runtime verification.

Project policy (database version, identifier scheme, deployment determinism) is discovered from the repository's own docs, config, and migrations, never assumed from a private default.
