# `argus/` — live cluster adapters around the frozen engine

Reads `docs/argus-go-live-task.md` for scope. The deterministic core
(`argus_engine.py`, `orchestrator.py`, `fixtures/`) is **frozen** — `argus/`
only adds the live read-only collector, scanner adapters, CLI, and RBAC needed
to point the engine at a real cluster.

## Phase 1 (this commit) — `argus/inventory.py`

Read-only Kubernetes inventory collector that emits the exact dict shape
`argus_engine.Cluster` consumes (`workloads`, `rbac`, `secrets`,
`networkPolicies`, `namespaces`, `cluster`, `scannedAt`).

### Hard guarantees (verified by tests)

| Guarantee | Test |
|---|---|
| Never reads or persists Secret `.data` | `SecretCollectionTests.test_secret_data_never_present_anywhere_in_output` |
| Works under RBAC without `get/list` on `secrets` | `SecretCollectionTests.test_collector_does_not_call_list_secret` (fake CoreV1 omits `list_secret_*`) |
| Engine constructs a `Cluster` from collector output and answers `sa_can_read_secrets` / `reachable_secrets` / `netpol` | `EngineCompatibilityTests` |
| `exposedVia` derived from Services + Ingresses | `ExposureTests` |
| Wildcard RBAC rule (`*`) surfaces `secrets` so engine's literal check matches | `RbacProjectionTests.test_wildcard_resource_expands_to_include_secrets` |

### How secret reachability is derived without listing Secrets

The deployed read-only RBAC (Phase 4) intentionally does **not** grant
`get/list` on `secrets`. The collector therefore harvests Secret references
from pod templates — `volumes[].secret`, `volumes[].projected.sources[].secret`,
`containers[].env[].valueFrom.secretKeyRef`, `containers[].envFrom[].secretRef` —
and emits metadata only (`id`, `namespace`, `type`, `sensitivity`). Sensitivity
is a name/type heuristic (`*cred*`, `*token*`, `kubernetes.io/tls`, etc.).

If a future product decision grants `get` on Secrets, the collector can be
extended to list directly — `.data` would still be stripped before any
in-memory persistence. That is an explicit, separate decision with its own
RBAC change.

### NetworkPolicy → engine match shape

The engine's `Cluster.netpol(namespace, appliesTo, ingress)` does a literal
three-way equality check. The collector emits one entry per
(namespace, matched-workload-name) pair with `ingress = "deny-external"` when
the policy denies all inbound traffic (`policyTypes: [Ingress]` with empty/no
`ingress` rules); `"custom"` for more permissive shapes. This is exactly what
the fixture uses and what `verify_controls` in the engine matches.

## Running the tests

No external deps beyond `PyYAML` (used by the engine, not by the collector
itself):

```bash
python3 -m pip install -r requirements.txt   # kubernetes + pyyaml
python3 -m unittest argus.tests.test_inventory -v
```

The collector itself imports `kubernetes` **lazily** inside `_load_apis`, so
unit tests that hand-build an `Apis` bundle run on a stock Python install
without the client.

## Live cluster validation (manual, not in CI yet)

Phase 1 doesn't ship a smoke script yet (that's Phase 5). To validate
field-by-field against a real cluster today:

```bash
kind create cluster
kubectl apply -f deploy/rbac.yaml          # Phase 4 — coming
python3 -c "import json, argus.inventory as inv; \
            print(json.dumps(inv.collect_inventory('kind-kind'), indent=2))"
```

Then sanity-check against `kubectl get deploy,svc,ing,netpol,rolebindings -A -o json`.

## Phase 2 — `argus/scanners.py`

Real adapters for **Trivy** (per-image CVE scan), **kube-bench** (CIS
benchmark on the cluster), and **Kubescape** (posture controls). Each
adapter:

* shells out to its binary, parses the JSON, normalises to the engine's
  frozen Finding shape;
* falls back cleanly when the binary is missing or fails — the run reports
  `skipped` / `errored` per scanner instead of crashing;
* treats scanner text as hostile input (length-bounded, control chars
  stripped) so it's safe to flow into a downstream model context.

`scanners.run_all(inventory)` returns a `ScanRun` containing
`findings: list` and `scanners: list[ScannerResult]`. Phase 3's CLI will
fold the scanner metadata into the report.

### Target mapping rules

| Scanner | Source target | Engine target |
|---|---|---|
| Trivy | image | every workload id running that image (1:N — same CVE on every workload using the image, exactly like the PoC fixture) |
| kube-bench | control-plane / node | literal `"cluster"` |
| Kubescape | `resourceID` (e.g. `apps/v1/Deployment/payments/invoice-api`) | `"<ns>/<name>"`, or `"cluster"` for cluster-scoped Kinds |

### Tests

```bash
python3 -m unittest argus.tests.test_scanners -v
```

Highlights:
* `TrivyAdapterTests.test_two_workloads_share_image_yield_one_finding_each` —
  pins the per-workload duplication that produces the engine's "same CVE,
  different priority" headline.
* `RunAllOrchestratorTests.test_missing_scanners_do_not_crash_and_are_reported_as_skipped`
  — proves the fail-safe degrade behaviour.
* `EngineRoundTripTests.test_engine_correlates_scanner_output_with_inventory`
  — feeds the Phase-1 inventory + Phase-2 scanner output into the **frozen**
  `argus_engine.correlate` and confirms ≥1 attack path emerges with risk ≥80,
  the same shape the PoC fixtures produce.

## Phase 3 — `argus/cli.py`

The `argus scan` entry point. Single command, full pipeline:

```bash
python3 -m argus.cli scan \
    --kubeconfig ~/.kube/config --context my-cluster \
    --accepted-risks ./accepted-risks --out ./out
```

Pipeline (all read-only): `collect_inventory()` → `scanners.run_all()` →
`eng.load_accepted_risks()` → `eng.correlate()` → write `out/report.md` +
`out/report.json` (JSON includes a `metadata.scanners` block listing which
scanners ran) → print a PoC-shape summary.

### Flags

| Flag | Effect |
|---|---|
| `--kubeconfig PATH` | kubeconfig file (default `KUBECONFIG` env / `~/.kube/config`) |
| `--context NAME` | kube context |
| `--in-cluster` | use the mounted SA token (for Job/CronJob mode) |
| `--cluster-name NAME` | label recorded in the report (default: context name) |
| `--accepted-risks DIR` | directory of `.md` policies — loaded and applied by the engine |
| `--out DIR` | output directory (default `./out`) |
| `--images-only` | run only Trivy; skip kube-bench + Kubescape |
| `--quiet` | suppress info logging |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed (findings are *not* a failure) |
| 1 | Unexpected error |
| 2 | Cluster unreachable (config / auth / network) |

### Tests

```bash
python3 -m unittest argus.tests.test_cli -v
```

Pinned invariants: report files written with engine output preserved + an
additive `metadata.scanners` block, markdown gets a `## Scanners` table,
missing scanners degrade to `skipped` (run succeeds), cluster-unreachable
returns exit 2 without writing any files, `--accepted-risks DIR` triggers
the engine's accept-and-verify flow, `--images-only` skips kube-bench +
Kubescape, and the engine's headline behaviour ("same CVE — exposed root
workload Critical, dormant clone Low") reproduces through the live CLI path.

## Phase 4 — deploy + Dockerfile

In-cluster deployment as a read-only Job (`deploy/job.yaml`) or daily CronJob
(`deploy/cronjob.yaml`), both bound to the `argus` ServiceAccount provisioned
by `deploy/rbac.yaml`. The image is built from the top-level `Dockerfile`.

### What ships

| File | What it does |
|---|---|
| `deploy/rbac.yaml` | Namespace + SA + ClusterRole + ClusterRoleBinding. Only `get/list/watch` verbs, **no `secrets`**, no wildcards, no exec/portforward/proxy, no nodes. |
| `deploy/job.yaml` | One-shot scan Job — nonroot, no privilege escalation, read-only root FS, all caps dropped, no host namespaces. |
| `deploy/cronjob.yaml` | Same as the Job but on a daily 03:00 UTC schedule with `concurrencyPolicy: Forbid`. |
| `Dockerfile` | Two-stage build: stage 1 fetches pinned `trivy` / `kube-bench` / `kubescape` releases, stage 2 is Python 3.12-slim with our code, runs as UID 65532, entrypoint `python3 -m argus.cli`. |

### Quickstart on a real cluster

```bash
# 1. Build the image (or point the manifests at a registry image).
docker build -t ghcr.io/your-org/argus:dev .

# 2. Apply RBAC (read-only).
kubectl apply -f deploy/rbac.yaml

# 3. Run a one-shot scan.
kubectl apply -f deploy/job.yaml
kubectl logs -n argus-system -l app.kubernetes.io/name=argus -f

# or schedule daily:
kubectl apply -f deploy/cronjob.yaml
```

### Tested invariants (`argus.tests.test_deploy`)

* `argus-readonly` ClusterRole has **no** `secrets`, `pods/exec`,
  `pods/portforward`, `pods/proxy`, `nodes`, `nodes/proxy`, `nodes/stats`.
* All verbs are exactly `get` / `list` / `watch` — anything else fails the
  test before it can ship.
* No wildcards anywhere (resources, verbs, apiGroups).
* ClusterRoleBinding targets the `argus` SA in `argus-system`, nothing else.
* Both Job and CronJob run nonroot, with `readOnlyRootFilesystem: true`,
  `allowPrivilegeEscalation: false`, all capabilities dropped, and no
  `hostNetwork` / `hostPID` / `hostIPC`.

Run them with:

```bash
python3 -m unittest argus.tests.test_deploy -v
```

## Phase 5 — smoke test on kind

End-to-end proof on a throwaway kind cluster.

```bash
scripts/smoke.sh            # default: from-host scan via the argus SA token
scripts/smoke.sh --build    # also docker-build the image and kind-load it
scripts/smoke.sh --keep     # leave the cluster + outputs for inspection
```

Prereqs: `kind`, `kubectl`, `python3`, `trivy`. Trivy is mandatory because the
attack-path assertion needs real CVE rows on the seeded vulnerable image.

What it proves (DoD §6):

1. `deploy/rbac.yaml` applies cleanly to a real API server.
2. The seed workloads (`test/vulnerable-workloads.yaml`) roll out.
3. `argus scan` succeeds using **only** the `argus` SA's read-only token —
   the shipped RBAC is sufficient.
4. The report contains ≥1 attack path anchored on the vulnerable workload.
5. The vulnerable workload outranks the benign one on top-finding score.
6. No Secret `.data` (and no seed Secret value) appears anywhere in the
   report.

### Tested invariants (no cluster required)

`argus.tests.test_smoke_artifacts` parses both files and pins the shape:

* `vulnerable-web` runs as root, has a Service + Ingress, and a SA bound to a
  Role granting `get/list` on Secrets in `argus-smoke`.
* `benign-internal` runs nonroot, no Service/Ingress points at it, and a
  NetworkPolicy denies external ingress in the deny-external shape the engine
  recognises.
* The smoke script uses `set -euo pipefail`, asserts every prerequisite, and
  authenticates as the `argus` SA (never `cluster-admin`).

## Phase 6 — `argus bootstrap csr` (out-of-cluster public-key connect)

Adds a second cluster-connect method alongside Helm. The cluster signs a
short-lived client cert that it explicitly approves; the agent then runs
read-only as that cert identity. Spec: `docs/PUBKEY_CONNECT_SPEC.md`;
wire contract: `docs/PUBKEY_CONNECT_CONTRACT.md`.

```bash
# kind / dev: auto-approve + clean up at exit
python3 -m argus.cli bootstrap csr \
    --enroll ent_<token-from-the-UI> \
    --control-plane https://control-plane.example.com \
    --auto-approve --cleanup

# production: print the kubectl approve command and wait for an admin
python3 -m argus.cli bootstrap csr \
    --enroll ent_<token-from-the-UI> \
    --control-plane https://control-plane.example.com
```

### What it does

1. Generates a fresh EC P-256 (or RSA-2048 fallback) keypair locally in a
   `0600` temp file with `atexit` cleanup. The private key **never leaves
   your machine** and is never logged or POSTed.
2. Builds a CSR with `CN=argus-agent-<6-hex>`, `O=argus-readonly`,
   `signerName=kubernetes.io/kube-apiserver-client`.
3. Submits the CSR to the cluster.
4. Either (default) prints `kubectl certificate approve <name>` and polls
   until approved+issued, or (with `--auto-approve`) patches the approval
   subresource itself.
5. Applies the same read-only RBAC the Helm chart uses (reuses the existing
   `argus-readonly` ClusterRole if present, otherwise creates it) and binds
   it via a new ClusterRoleBinding to **both** the cert's `User=CN` and
   `Group=O` subjects.
6. Assembles a scoped agent kubeconfig at `--out` (default
   `./argus-agent.kubeconfig`, mode `0600`).
7. Runs `argus scan` against that kubeconfig.
8. POSTs the resulting report to `<control-plane>/api/scans` with the
   enrollment token as a Bearer credential.
9. Optionally (`--cleanup`) deletes the CSR + ClusterRoleBinding on exit.

### Security — read this

* **Kubernetes client certificates are NOT revocable.** The only mitigation
  is a short TTL — `--ttl` defaults to `3600s` and the CLI prints the
  cert's `NotAfter` timestamp on exit. Use `--cleanup` for ephemeral
  scans.
* Approving the CSR and creating the ClusterRoleBinding requires
  `cluster-admin` on the kubeconfig you point `--admin-kubeconfig` at.
  This is intentional — the cluster explicitly "admits" the agent. The
  bound RBAC is the **same** read-only set the Helm chart grants
  (`get/list/watch`, NO `secrets` verbs anywhere).
* `--auto-approve` defaults **OFF** and is documented as kind/dev only.
* The control-plane only ever sees the CSR and the enrollment token; it
  never receives the private key, the issued cert, or any cluster
  credential.

### Flags

| Flag | Effect |
|---|---|
| `--enroll TOKEN` | Single-use, short-TTL bearer token from the UI (required) |
| `--control-plane URL` | Control-plane base URL (required) |
| `--ttl SECONDS` | Cert lifetime (default 3600) |
| `--auto-approve` | Approve via admin kubeconfig (kind/dev only; defaults OFF) |
| `--cleanup` | Delete the CSR + CRB on exit |
| `--out PATH` | Scoped agent kubeconfig path (default `./argus-agent.kubeconfig`) |
| `--admin-kubeconfig PATH` | Admin kubeconfig (default `$KUBECONFIG`/`~/.kube/config`) |
| `--admin-context NAME` | Kube context inside the admin kubeconfig |
| `--cluster-id ID` | Control-plane cluster id (default: resolve via `/api/clusters/self`) |
| `--quiet` / `--verbose` | Log levels |

### Tests

```bash
python3 -m pytest argus/tests/test_bootstrap.py -v
```

27 cases pin: keypair shape, 0600 private-key perms, CSR CN/O/signer,
events_client Authorization + JSON body + 5xx retry, detail-payload size
cap, auto-approve patches the Approved condition, RBAC is idempotent
against an existing ClusterRole, ZERO secrets verbs in the read-only
rules, `--cleanup` deletes both objects on success AND on failure, stage
failures POST `error` events and exit non-zero, and the full happy-path
event sequence matches the FROZEN wire contract.

## Done

All five phases of `docs/argus-go-live-task.md` are implemented:

| Phase | Status |
|---|---|
| 1 — `argus/inventory.py` | ✓ |
| 2 — `argus/scanners.py` | ✓ |
| 3 — `argus/cli.py` | ✓ |
| 4 — `deploy/` + `Dockerfile` | ✓ |
| 5 — `scripts/smoke.sh` + `test/vulnerable-workloads.yaml` | ✓ |

Engine frozen throughout. Run the full suite with:

```bash
python3 -m unittest discover -s argus/tests
```
