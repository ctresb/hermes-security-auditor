# Contributing

Contributions should improve audit quality, not add generic checklist noise.

## Good additions

- New vulnerability class with attacker chain, evidence, remediation, and verification.
- Better Rust/PostgreSQL/OAuth/crypto examples.
- Better dynamic verification workflow.
- Reduced false positives or clearer severity guidance.

## Finding quality bar

Every serious finding pattern should answer:

1. Who can reach it?
2. What input does the attacker control?
3. What guard exists and why does it fail?
4. What is immediate impact?
5. What chain or second step does it unlock?
6. How can maintainers verify the fix?

## Style

- Keep `SKILL.md` actionable.
- Move long deep-dives to `references/`.
- Avoid private project defaults. If a policy is project-specific, say so.
- Do not claim command results unless the command was actually run.
