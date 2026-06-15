# Audit Methodology

The Rust security auditor uses an adversarial review loop:

1. Map attack surface and trust boundaries.
2. Run safe mechanical checks.
3. Review code paths manually.
4. Generate candidate findings.
5. Try to refute each finding end-to-end.
6. Dynamically verify migrations/tests when feasible.
7. Rank findings by severity and confidence.
8. Write remediation and verification steps.

Static review is not enough for database-backed systems. Race conditions, migrations, RLS gaps, pool state bleed, and conflict paths often appear only under runtime verification.
