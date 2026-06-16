# Cloud, Containers, Kubernetes & IaC Security

Companion to `backend-audit`. Deployment is part of the system: this pack adds the Dockerfile / docker-compose / Kubernetes-Helm / Terraform-IaC / cloud-IAM surfaces the base `SKILL.md` does not cover. Activate whenever any of those artifacts exist in the repo.

## A. Docker / Dockerfile

Required checks:
- **Pin base by digest.** Flag `FROM image:latest` or any unpinned/floating tag - non-reproducible builds, silent base-image drift. Correct: `FROM image:1.2.3@sha256:...`. Re-pin via a renovate/dependabot flow, not by hand.
- **Run as non-root.** No explicit `USER` (or `USER root`) means the container runs as UID 0 - a container escape inherits root. CWE-250 (Execution with Unnecessary Privileges). Correct: create an unprivileged user and `USER 10001` (numeric UID so K8s `runAsNonRoot` can verify it; a username can't be resolved against `/etc/passwd` by the kubelet).
- **No secrets in image layers / `ENV` / `ARG`.** `ARG`/`ENV` values and any `COPY`d secret persist in layer history and are extractable with `docker history` / `dive` even if a later layer `rm`s the file. CWE-798 (Use of Hard-coded Credentials), CWE-538 (Insertion of Sensitive Information into Externally-Accessible File). Correct: BuildKit `RUN --mount=type=secret,id=...` for build-time creds; runtime secrets via mounted files / orchestrator secrets, never baked.
- **Multi-stage builds.** Build deps, source, `.git`, and build-time creds must stay in the builder stage; the final stage `COPY --from=builder` only the binary. A single-stage Rust image ships the whole `cargo`/source/`target/` tree.
- **`.dockerignore`** must exclude `.git`, `.env`, `target/`, `*.pem`, `**/secrets*` - otherwise `COPY . .` leaks them into context and layers.
- **Trusted, minimal base.** Prefer `distroless` / `scratch` (static-linked Rust via musl) / minimal slim images - smaller attack surface, no shell to pivot from. Flag full `ubuntu`/`debian` for a single static binary.
- **Image vuln scanning** in CI: `trivy image --severity HIGH,CRITICAL --exit-code 1 <img>` or `grype <img>`. Flag absence of any scan gate. Also `trivy fs` / `trivy config` for the Dockerfile itself (gate alongside the CI hardening in `references/supply-chain-ci-cd-security.md`).
- **Healthcheck / least install**: no `curl|bash`, no `--no-check-certificate`, no adding `sudo`. Pin apt/apk package versions where reproducibility matters.

## B. docker-compose production traps

Treat any `docker-compose.yml` used beyond local dev with prod scrutiny:
- **Default / weak secrets** in `environment:` (`POSTGRES_PASSWORD: postgres`, `JWT_SECRET: changeme`, `REDIS` with no auth). CWE-1188 (Initialization of a Resource with an Insecure Default), CWE-798. Use `env_file` / `secrets:` and require non-default values.
- **Unnecessarily published ports.** `ports: ["5432:5432"]` / `["6379:6379"]` binds to `0.0.0.0` on the host and bypasses cloud firewalls/SGs - Postgres/Redis become internet-reachable. Use `expose:` (intra-network only) or bind to `127.0.0.1:5432:5432`. Internet-reachable datastore with weak/default creds is CRITICAL.
- **`network_mode: host`** removes network namespace isolation; the container shares the host stack (and can reach `127.0.0.1` services).
- **`privileged: true`** / broad `cap_add` / `security_opt: [seccomp:unconfined, apparmor:unconfined]` - escape-equivalent. Flag any.
- **Bind mounts exposing the host**: `- /:/host`, `- /var/run/docker.sock:/var/run/docker.sock` (docker socket = host root / RCE - CRITICAL), `- /etc:...`. Prefer named volumes; mount the socket only for a trusted, isolated workload.

## C. Kubernetes - Pod Security Standards (privileged / baseline / restricted)

Target the **Restricted** PSS profile for app workloads; flag deviations. Enforce cluster-side via Pod Security Admission labels (`pod-security.kubernetes.io/enforce: restricted`) so manifests can't silently regress.

Red flags (each is escalation/escape-adjacent):
- `securityContext.privileged: true` - full host access. CRITICAL.
- `hostNetwork: true` / `hostPID: true` / `hostIPC: true` - namespace sharing; `hostPID` lets a container see/signal host processes.
- `volumes[*].hostPath` - mounts host filesystem (e.g. `/`, `/var/run/docker.sock`, `/var/lib/kubelet`) = node compromise. CRITICAL when writable or sensitive.
- Missing **resource `requests`/`limits`** (CPU/memory) -> noisy-neighbor / node OOM DoS (CWE-770; ties to async DoS in `SKILL.md` §4).
- Missing **`NetworkPolicy`** for sensitive workloads - default K8s networking is allow-all pod-to-pod; without policy a compromised pod reaches the DB/internal services laterally. Require default-deny + explicit allows.
- Over-broad **RBAC**: `ClusterRole` with `verbs`/`resources`/`apiGroups: ["*"]`, `secrets` read across namespaces, `create pods`/`pods/exec`/`escalate`/`bind`, or binding to the `cluster-admin` ClusterRole. Wildcard cluster RBAC is CRITICAL.
- `automountServiceAccountToken` not disabled where the pod doesn't call the K8s API - a mounted SA token is a credential an attacker exfiltrates (and a prime SSRF target, see §E). Set `automountServiceAccountToken: false` on the SA/pod.
- Mutable container tags (`image: app:latest`) and `imagePullPolicy: Always` masking unpinned images - pin by digest as in §A.

Required `securityContext` (Restricted-aligned):
- `runAsNonRoot: true` and a numeric `runAsUser` (e.g. `10001`).
- `allowPrivilegeEscalation: false`.
- `seccompProfile.type: RuntimeDefault` (or `Localhost`).
- `capabilities.drop: ["ALL"]` (add back only specific needed caps, never `NET_ADMIN`/`SYS_ADMIN`).
- `readOnlyRootFilesystem: true` with an `emptyDir` for `/tmp` - note this is recommended hardening beyond the official PSS Restricted set, which does not itself mandate it; still flag its absence for app pods.
- AppArmor (`securityContext.appArmorProfile` field, GA since K8s v1.30; the older `container.apparmor.security.beta.kubernetes.io/<container>` annotation is deprecated) or SELinux where available.
- Validate manifests with `kubeconform` + `trivy config` / `checkov -d .` / `kube-score`; OPA Gatekeeper or Kyverno as admission policy-as-code.

## D. IaC (Terraform / CloudFormation / Pulumi)

Static-scan every plan/module; these are the high-severity classes:
- **Public storage**: S3 `acl = "public-read"`, missing `aws_s3_bucket_public_access_block` (all four flags `true`), GCS `allUsers`/`allAuthenticatedUsers`, public Azure blob containers. Public bucket holding non-public data is CRITICAL. CWE-732 (Incorrect Permission Assignment for Critical Resource), OWASP IaC Cheat Sheet.
- **Publicly reachable databases**: RDS/Aurora/Cloud SQL with `publicly_accessible = true`, or in a public subnet with an internet route.
- **`0.0.0.0/0` on sensitive ports**: security-group / firewall ingress `cidr_blocks = ["0.0.0.0/0"]` on 22 (SSH), 3389 (RDP), 5432 (Postgres), 6379 (Redis), 27017, 9200, 3306. World-open admin/DB port is CRITICAL. CWE-284 (Improper Access Control).
- **Wildcard IAM**: policy `Action: "*"` and/or `Resource: "*"`, `Principal: "*"` on a resource policy, `Effect: Allow` with no condition. CWE-269 (Improper Privilege Management). See §E for least privilege.
- **Unencrypted at rest**: storage/queues/DB/backups/snapshots/logs without encryption - RDS `storage_encrypted`, EBS encryption, S3 default SSE/KMS, SQS/SNS KMS, EFS, ElastiCache at-rest+in-transit. CWE-311 (Missing Encryption of Sensitive Data).
- **KMS hygiene**: enable `enable_key_rotation = true`; key policies must follow least privilege and **separate key administrators from key users** (admins manage the key but cannot decrypt; apps use but cannot delete/alter policy) - no `kms:*` to a broad principal. See AWS KMS key-policies guidance.
- **No TLS in transit**: load balancers / API endpoints terminating plain HTTP, RDS without `require_ssl`, ELB listeners on `:80` without redirect.
- **Drift / state**: secrets in `*.tfstate` (state holds plaintext) - store state in an encrypted, access-controlled backend; never commit `.tfstate`/`.tfvars` with secrets. Run drift detection (`terraform plan -detailed-exitcode`).
- **Scanners (gate in CI)**: `tfsec`, `checkov -d .`, `trivy config .` (covers tf/cfn/k8s/dockerfile), and OPA/`conftest test` for org policy-as-code. Flag absence of any IaC scan gate.

## E. Cloud IAM least privilege + instance metadata (IMDS)

- **Scope roles tightly**: one role per workload, granting only the specific actions on the specific resource ARNs it uses; condition keys (`aws:SourceVpc`, `aws:PrincipalTag`, `aws:SourceArn`) to constrain. No long-lived user access keys for services - use instance/pod identity (IRSA / Workload Identity / managed identity). Flag `AdministratorAccess`, `*:*`, and shared roles. AWS IAM best practices.
- **Require IMDSv2.** This ties directly to SSRF (`SKILL.md` §"SSRF, URL Fetching, and Webhooks"): an SSRF that reaches `http://169.254.169.254/...` (or the GCP/Azure equivalent) **steals the instance role's temporary credentials**. IMDSv1 is a single unauthenticated GET - trivially SSRF-exploitable. IMDSv2 requires a PUT to `/latest/api/token` to obtain a session token (carried back in the `X-aws-ec2-metadata-token` header) and a default hop limit of 1, which most SSRF primitives cannot perform. Require in Terraform:
  - `metadata_options { http_tokens = "required"; http_put_response_hop_limit = 1; http_endpoint = "enabled" }` (set the hop limit higher only if a container layer must proxy IMDS - that re-opens the SSRF risk, so flag it).
  - For EKS, prefer IRSA over node-role credential inheritance, and set the node hop limit so pods can't reach IMDS at all.
- App-side SSRF defenses (allowlist, resolve-and-block link-local `169.254.0.0/16` and metadata IPs, no blind redirects) remain mandatory - IMDSv2 is defense-in-depth, not a substitute. Cross-ref `SKILL.md` SSRF remediation.
- Over-broad pod RBAC / mounted SA tokens (§C) are the in-cluster analogue: SSRF to the Kubernetes API (`https://kubernetes.default.svc`) with a powerful token escalates the same way.

## F. Backup / restore

- **Encrypted backups** (KMS/SSE) with access separated from production write paths; offsite/cross-account copy so a compromised prod account can't delete recovery data (CWE-922 - Insecure Storage of Sensitive Information applies to plaintext backups).
- **Tested restore evidence**: an untested backup is not a backup. Require a documented, recent restore drill, not just "backups are enabled".
- **RPO/RTO stated** and matched to the backup cadence (hourly snapshots can't deliver a 5-minute RPO). PITR enabled for the DB where the RPO demands it.
- Backups must inherit the same data-classification, retention, and deletion rules as production (right-to-erasure must reach backups). Detection/IR and privacy depth: see `references/detection-privacy-incident-response.md`.

Cross-references: `SKILL.md` §"SSRF, URL Fetching, and Webhooks", §5 "Secrets, TLS, Database Privileges, and Deployment Defaults", and §4 (async DoS); `references/postgres-deep-and-pooling-audit.md` (DB role/privilege separation); `references/web-crypto-hardening-rust.md` (TLS/secret hygiene in the app); `references/supply-chain-ci-cd-security.md` (CI scan-gate + pipeline hardening); `references/rust-unsafe-fuzzing-tooling.md` (unsafe/fuzz/build-script tooling); `references/detection-privacy-incident-response.md` (IR/backups/privacy).

## Sources
- Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- NIST SP 800-190, Application Container Security Guide: https://csrc.nist.gov/pubs/sp/800/190/final
- OWASP Infrastructure as Code Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html
- Docker Engine security: https://docs.docker.com/engine/security/
- AWS IAM best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- AWS KMS key policies: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
