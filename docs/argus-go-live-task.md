# Claude Code task — ARGUS: make it run live against a real cluster

> **Feed this file to Claude Code.** It turns the validated proof-of-concept into a
> working tool that connects to a real Kubernetes cluster (read-only) and produces
> a real posture report.

## 0. Read first (in this order)

1. `docs/argus-scanner-agent.md` — the **validated core**. The deterministic engine
   (`argus_engine.py`), the agent orchestrator (`orchestrator.py`), the accepted-risk
   logic, and the normalized **inventory** and **findings** schemas are already
   correct and tested. **Treat the engine as frozen.**
2. The `PROD:` table in §8 of that doc — it lists exactly which stubs to replace.

## 1. Goal

Replace the fixture-reading stubs with real, **read-only** cluster collection and
real scanner adapters, behind a CLI, so this command produces a real report:

```bash
argus scan --kubeconfig ~/.kube/config --context my-cluster \
           --accepted-risks ./accepted-risks --out ./out
```

The engine's `correlate()` and `render_markdown()` consume the live data unchanged.

## 2. What you are starting from (do NOT modify)

- `argus_engine.py` — scoring, attack-path, accepted-risk governance. **Frozen.**
  If you believe a change is required, stop and surface it; do not edit silently.
- The normalized schemas it expects:
  - **Finding**: `{ id, source, type("cve"|"misconfig"|"cis"), cve?, cvss?, ruleId?, severity, target, title }`
  - **Inventory**: `{ cluster, scannedAt, namespaces, workloads[], rbac[], secrets[], networkPolicies[] }`
    where a workload is `{ id:"ns/name", kind, namespace, replicas, running, image, serviceAccount:"ns/sa", runAsRoot, privileged, exposedVia:[...] }`
- `orchestrator.py` — the agent's tool surface and defensive system prompt. Keep the
  tool names and the orchestration shape; only swap the tool *bodies* for real ones.

## 3. What to build (new modules)

Create a package `argus/` with:

### 3.1 `argus/inventory.py` — read-only cluster collector
- Use the official `kubernetes` Python client (in-cluster config if a SA token is
  mounted, else kubeconfig + context).
- Build the **Inventory** exactly in the frozen schema:
  - **workloads** from Deployments/StatefulSets/DaemonSets: `running` = readyReplicas > 0
    (DaemonSets: desired > 0 and available > 0); `image` = first app container image;
    `serviceAccount` = `"<ns>/<spec.serviceAccountName or 'default'>"`;
    `runAsRoot` = not (runAsNonRoot true or runAsUser>0) at pod/container level;
    `privileged` = any container `securityContext.privileged`.
  - **exposedVia**: derive from Services + Ingresses. A workload is publicly exposed if
    a Service of type LoadBalancer selects its pods, or an Ingress routes to a Service
    that selects its pods → add `"ingress:<host>"` / `"loadbalancer:<svc>"`. Otherwise omit.
  - **rbac**: from Roles/ClusterRoles + RoleBindings/ClusterRoleBindings, resolve per
    ServiceAccount the `{verbs, resources, scope}` it holds. You only need this to
    answer "can this SA read Secrets" — that is an RBAC question, not a Secret-read.
  - **secrets**: enumerate Secret **names/namespaces/types only**. Set `sensitivity`
    by heuristic (name/label/annotation patterns like `*cred*`, `*token*`, `*db*`,
    `type=kubernetes.io/tls`). **Never read or store `.data`.** If you list Secrets,
    strip `.data` immediately and never persist it.
  - **networkPolicies**: namespace + the workload/selector they apply to + whether they
    deny external ingress (shape it so `Cluster.netpol()` in the engine can match).

### 3.2 `argus/scanners.py` — real scanner adapters
Replace the `run_*` stubs. Each shells out, parses JSON, and normalizes to **Finding**:
- `run_trivy(images)` → `trivy image --format json <img>` per unique image (or
  `trivy k8s --format json` cluster mode). Map vulnerabilities → findings; `target`
  must be the inventory workload id(s) running that image.
- `run_kube_bench()` → run kube-bench `--json` (in-cluster Job is the clean way);
  `target: "cluster"` for control-plane/node checks.
- `run_kubescape()` → `kubescape scan --format json --format-version v2`; map each
  failed control to a finding on the affected `ns/name`.
- If a scanner binary is missing or errors, log a warning and skip it — never crash
  the run. Record which scanners ran in the report metadata.

### 3.3 `argus/cli.py` — entry point
- `argus scan [--kubeconfig] [--context] [--in-cluster] [--accepted-risks DIR] [--out DIR] [--images-only]`
- Pipeline: collect inventory → run available scanners → `eng.load_accepted_risks(dir)`
  → `eng.correlate(inv, findings, ars)` → write `out/report.md` + `out/report.json`
  via `eng.render_markdown`. Print the same summary the PoC prints.
- Exit non-zero only on a real failure (cluster unreachable), not on findings.

### 3.4 Deployment + RBAC
- `deploy/rbac.yaml` — a **read-only** ServiceAccount + ClusterRole + ClusterRoleBinding.
  Verbs limited to `get,list,watch`. Resources: pods, deployments, statefulsets,
  daemonsets, services, ingresses, networkpolicies, serviceaccounts, roles,
  rolebindings, clusterroles, clusterrolebindings.
  **Do NOT grant `get/list` on `secrets`** — derive secret reachability from RBAC +
  pod volume mounts instead. (If product later needs Secret metadata, that is a
  separate, explicit decision with its own RBAC + `.data` stripping.)
- `deploy/job.yaml` + `deploy/cronjob.yaml` — run ARGUS in-cluster as a read-only Job
  (on-demand) and CronJob (scheduled), mounting the SA token.
- `Dockerfile` — Python + the tool, with trivy/kube-bench/kubescape installed (or a
  documented sidecar/init approach). `requirements.txt`: `kubernetes`, `pyyaml`.

### 3.5 `scripts/smoke.sh` — prove it on a throwaway cluster
- `kind create cluster`; apply `test/vulnerable-workloads.yaml` (you create it): a
  Deployment running as root on an old image, with an over-permissioned SA that can
  get Secrets, fronted by an Ingress; plus a benign internal workload.
- Apply `deploy/rbac.yaml`; run `argus scan` against the kind context.
- Assert the report contains ≥1 attack path and that the benign workload's findings
  rank below the exposed one.

## 4. Guardrails (do not violate)

- **Read-only, always.** No write/patch/delete verbs in RBAC; no `kubectl apply`; no
  pod exec; no node SSH. The tool must function with a strictly read-only SA.
- **Never read or persist Secret `.data`.** Secret *reachability* comes from RBAC +
  mounts, not from reading secrets. Add a test asserting `.data` never appears in any
  collected object or output file.
- **Engine is frozen.** Add adapters/collectors/CLI around `argus_engine.py`; do not
  change its scoring, attack-path, or accepted-risk logic. Reproduce the PoC output on
  the fixtures as a regression test.
- **No offensive content, no model in the engine.** This is defensive scanning; the
  pipeline detects and reports, it never generates exploits or payloads. The optional
  model orchestration layer (orchestrator.py) stays orchestration + defensive
  reporting only; if you wire a real model later, sanitize scanner output before it
  enters the model's context and keep it out of any attack-generation reasoning.
- **Fail safe.** Missing scanner → skip with warning. Unreachable cluster → clear error.

## 5. Phases (one at a time; verify each before the next)

1. `inventory.py` collector → produces the frozen Inventory schema from a live cluster;
   validate field-by-field against a kind cluster.
2. `scanners.py` adapters → Trivy first (prove normalization + target mapping), then
   kube-bench, then Kubescape.
3. `cli.py` wiring → live report from real data, reusing the engine untouched.
4. `deploy/` RBAC + Job/CronJob + Dockerfile.
5. `scripts/smoke.sh` + `test/vulnerable-workloads.yaml`.

## 6. Definition of done

- `argus scan` against a kind cluster with the seeded vulnerable workloads produces
  `out/report.md` + `out/report.json` containing ≥1 attack path, using the engine
  unchanged.
- RBAC contains only `get,list,watch` and **no** secrets permission; the run succeeds
  under it.
- A test proves Secret `.data` is never collected, logged, or written.
- A regression test reproduces the PoC's fixture output exactly (engine unchanged).
- Accepted-risk `.md` files in `--accepted-risks DIR` are loaded and applied to live
  findings, including the auto-reopen-on-failed-control behavior.
- Missing scanners degrade gracefully; the report records which scanners ran.

## 7. How to run this in Claude Code

1. Put `argus-scanner-agent.md` and this file in `docs/` and create the PoC files from
   `argus-scanner-agent.md` §6 (engine, orchestrator, fixtures) if not already present.
2. Prompt: *"Implement docs/argus-go-live-task.md. The validated core is in
   docs/argus-scanner-agent.md — keep `argus_engine.py` frozen and only build the
   adapters/collector/CLI/RBAC around it. Do Phase 1 from §5 first and stop for review."*
3. Work phase by phase. Run `scripts/smoke.sh` before considering it done.
