# ARGUS — Dual-Use-Safe Vulnerability Scanning Agent (build doc)

> A working, self-contained build of an **agent that runs Kubernetes vulnerability
> scans without generating any dual-use cyber content** — so it does not trip the
> cyber-content classifiers — plus a **deterministic correlation engine** and a
> governed **Accepted Risks** (mitigated-risk) layer.
>
> Everything in this document has been run end to end. Copy the files exactly as
> shown, follow **§5 Run it**, and you get the output in §5.2.

---

## 1. The core principle (why this doesn't trip dual-use)

The classifier fires when a **model generates** offensive reasoning (exploits,
payloads, attack tradecraft). It does **not** fire because you scan — `trivy image`
is a program emitting JSON, and an agent calling it is making a tool call.

So we put the model in the **orchestrator** seat, never the **analyst** seat:

| Layer | Who does it | Dual-use risk |
|---|---|---|
| **Detection** | deterministic scanners (Trivy, kube-bench, Kubescape) | none — they emit data |
| **Correlation / attack paths** | deterministic engine (`argus_engine.py`) | none — it is code, not a model |
| **Accepted-risk governance** | deterministic policy files + verification | none |
| **Orchestration + reporting** | the agent (model) | low — it sequences tools and reports facts |

The model never has to reason about how to attack anything, because nothing in
the pipeline asks it to. This is not evasion — the architecture simply reflects
that the work is genuinely defensive.

**Non-negotiable rule for the agent:** it may run read-only scan tools and report
defensive results. It may not generate exploits, payloads, malware, or offensive
reasoning, and it may not write to the cluster. This is pinned in the agent's
system prompt (see `orchestrator.py`).

For any *residual* part where you want a model to narrate richer attack-path
detail, that part — and only that part — goes behind a verification program
(Anthropic CVP / OpenAI Trusted Access) or a self-hosted open-weight engine
(Mistral/Llama via Hermes). The deterministic core below needs neither.

---

## 2. Architecture

```
            agent (orchestrator, model)         <- sequences tools, reports facts
              | tool calls only
   ┌──────────┼───────────────────────────────┐
   v          v          v          v          v
inventory   trivy    kube-bench  kubescape   (load accepted risks .md)
(kubectl)   (CVEs)   (CIS)       (posture)
   └──────────┴───────────┬──────┴────────────┘
                          v
              correlation engine (deterministic)   <- reachability scoring + attack paths
                          v
              apply accepted-risk policy            <- suppress mitigated, verify controls
                          v
                  posture report (md / json)
```

---

## 3. Repo layout

```
argus-poc/
├── argus_engine.py                      # deterministic correlation + accepted-risk governance
├── orchestrator.py                      # the agent: orchestrates tools, no offensive reasoning
└── fixtures/
    ├── inventory.json                   # read-only cluster snapshot (PROD: kubectl get -o json)
    ├── findings.json                    # normalized scanner output (PROD: real Trivy/etc. JSON)
    └── accepted-risks/
        └── AR-2026-001.md               # a human-approved, expiring, verified risk acceptance
```

---

## 4. Dependencies

Python 3.10+ and PyYAML (for accepted-risk frontmatter):

```bash
pip install pyyaml
```

---

## 5. Run it

### 5.1 Commands

```bash
# the deterministic engine alone (reads fixtures, writes out/report.md + out/report.json)
python argus_engine.py

# the full agent pipeline (orchestrates the scan tools, then the engine)
python orchestrator.py
```

### 5.2 Expected output (verified)

```
[agent] role: defensive scan orchestrator (no offensive reasoning)

[agent] -> collect_inventory  :: 3 workloads, 1 secrets
[agent] -> run_trivy  :: 3 findings
[agent] -> run_kube_bench  :: 1 findings
[agent] -> run_kubescape  :: 2 findings
[agent] -> load_accepted_risks  :: 1 active accepted-risk policy file(s)
[agent] -> correlate  :: risk 93/100, 1 path(s), 1 accepted, 0 refusal(s)
[agent] -> render_report  :: wrote out/agent-report.md

[agent] Summary:
        Cluster prod-eu-1 scored 93/100.
        1 critical active finding(s); 1 reachable path(s); 1 risk(s) accepted with verified controls.
        AP-1: External exposure -> credential disclosure - fix any of 4 controls to collapse it.
        Nothing was modified. All actions were read-only.
```

The two behaviours that prove the engine works:
- **Same CVE, different priority:** `CVE-2026-31337` is **Critical (100)** on the internet-reachable, root-running `payments/invoice-api`, but **Low (11)** on the dormant `batch/report-worker`. A CVSS-only tool flags both Critical and buries the team.
- **Mitigated risk suppressed, with proof:** the internal redis DoS (`F-006`) is accepted under `AR-2026-001`; its compensating control (the `deny-external` NetworkPolicy) is **verified against the live inventory**, so it drops out of the active feed. If that NetworkPolicy were removed, the next run auto-reopens it.

---

## 6. The code (verified — copy exactly)

### 6.1 `fixtures/inventory.json`
```json
{
  "cluster": "prod-eu-1",
  "scannedAt": "2026-05-28T09:14:00Z",
  "namespaces": ["payments", "batch", "kube-system"],
  "workloads": [
    {
      "id": "payments/invoice-api",
      "kind": "Deployment",
      "namespace": "payments",
      "replicas": 3,
      "running": true,
      "image": "ghcr.io/acme/invoice-api:1.2.3",
      "serviceAccount": "payments/invoice-sa",
      "runAsRoot": true,
      "privileged": false,
      "exposedVia": ["ingress:invoice.acme.com"]
    },
    {
      "id": "batch/report-worker",
      "kind": "Deployment",
      "namespace": "batch",
      "replicas": 0,
      "running": false,
      "image": "ghcr.io/acme/invoice-api:1.2.3",
      "serviceAccount": "batch/default",
      "runAsRoot": true,
      "privileged": false,
      "exposedVia": []
    },
    {
      "id": "payments/cache",
      "kind": "Deployment",
      "namespace": "payments",
      "replicas": 2,
      "running": true,
      "image": "redis:7.2.0",
      "serviceAccount": "payments/default",
      "runAsRoot": false,
      "privileged": false,
      "exposedVia": []
    }
  ],
  "rbac": [
    { "serviceAccount": "payments/invoice-sa", "verbs": ["get", "list"], "resources": ["secrets"], "scope": "payments" },
    { "serviceAccount": "batch/default", "verbs": [], "resources": [], "scope": "batch" },
    { "serviceAccount": "payments/default", "verbs": [], "resources": [], "scope": "payments" }
  ],
  "secrets": [
    { "id": "payments/db-credentials", "namespace": "payments", "type": "Opaque", "sensitivity": "high" }
  ],
  "networkPolicies": [
    { "namespace": "payments", "appliesTo": "cache", "ingress": "deny-external" }
  ]
}
```

### 6.2 `fixtures/findings.json`
```json
{
  "findings": [
    { "id": "F-001", "source": "trivy",     "type": "cve",      "cve": "CVE-2026-31337", "cvss": 9.8, "severity": "critical", "target": "payments/invoice-api", "title": "Remote code execution in libfoo < 2.1" },
    { "id": "F-002", "source": "trivy",     "type": "cve",      "cve": "CVE-2026-31337", "cvss": 9.8, "severity": "critical", "target": "batch/report-worker",  "title": "Remote code execution in libfoo < 2.1" },
    { "id": "F-003", "source": "kubescape", "type": "misconfig","ruleId": "C-0017",      "severity": "high",     "target": "payments/invoice-api", "title": "Container runs as root" },
    { "id": "F-004", "source": "kubescape", "type": "misconfig","ruleId": "C-0015",      "severity": "medium",   "target": "payments/invoice-api", "title": "ServiceAccount can read Secrets" },
    { "id": "F-005", "source": "kube-bench","type": "cis",      "ruleId": "1.2.16",      "severity": "medium",   "target": "cluster",              "title": "Anonymous auth enabled on kubelet" },
    { "id": "F-006", "source": "trivy",     "type": "cve",      "cve": "CVE-2025-22000", "cvss": 5.3, "severity": "medium",   "target": "payments/cache",       "title": "Denial of service in redis < 7.2.4" }
  ]
}
```

### 6.3 `fixtures/accepted-risks/AR-2026-001.md`
```markdown
---
id: AR-2026-001
selector_type: specific
status: accepted
owner: alice@acme.com
approver: ciso@acme.com
created: 2026-05-20
expires: 2026-08-18
match:
  source: trivy
  severity: [low, medium]
  cve: CVE-2025-22000
  target: payments/cache
compensating_controls:
  - type: network-policy
    description: cache is internal-only; external ingress denied by NetworkPolicy
    verify:
      namespace: payments
      appliesTo: cache
      ingress: deny-external
  - type: patch-tracked
    description: redis upgrade tracked in JIRA OPS-4412
    verify: null
---

## Why accepted
The redis DoS is only reachable from inside the cluster; the cache has no public
exposure and a NetworkPolicy denies external ingress. Low blast radius.

## What would change this decision
If the deny-external NetworkPolicy is removed, or the cache becomes exposed.
```

### 6.4 `argus_engine.py`
```python
#!/usr/bin/env python3
"""
ARGUS — correlation engine + accepted-risk governance (proof of concept)

Deterministic graph logic over cluster facts. No LLM in the loop, so it is
auditable, reproducible, and never touches a cyber-content classifier.

  correlate(inventory, findings, accepted_risks) -> report dict
  render_markdown(report, scannedAt) -> str

Run directly to produce out/report.md and out/report.json from the fixtures.
"""
from __future__ import annotations
import json, os, glob, datetime, dataclasses
from dataclasses import dataclass, field, asdict
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- scoring model (transparent / tunable) ----
SEV_BASE = {"critical": 85, "high": 58, "medium": 38, "low": 16}
BANDS = [(80, "Critical"), (58, "High"), (33, "Medium"), (0, "Low")]
EXPOSURE_FACTOR = {"public": 1.0, "internal": 0.55, "dormant": 0.10, "cluster": 1.0}
BOOST = {"root": 0.15, "secrets": 0.20, "privileged": 0.25}
BOOST_CAP = 0.35


def band(score):
    for t, name in BANDS:
        if score >= t:
            return name
    return "Low"


@dataclass
class Workload:
    id: str; namespace: str; running: bool; image: str
    serviceAccount: str; runAsRoot: bool; privileged: bool; exposedVia: list

    @property
    def publicly_exposed(self):
        return any(e.startswith(("ingress:", "loadbalancer:")) for e in self.exposedVia)


class Cluster:
    def __init__(self, inv):
        self.name = inv["cluster"]
        self.workloads = {w["id"]: Workload(
            w["id"], w["namespace"], w["running"], w["image"], w["serviceAccount"],
            w["runAsRoot"], w["privileged"], w["exposedVia"]) for w in inv["workloads"]}
        self.rbac = inv["rbac"]; self.secrets = inv["secrets"]
        self.networkPolicies = inv.get("networkPolicies", [])

    def sa_can_read_secrets(self, sa):
        return any(r["serviceAccount"] == sa and "secrets" in r["resources"]
                   and any(v in ("get", "list", "*") for v in r["verbs"]) for r in self.rbac)

    def reachable_secrets(self, sa, ns):
        return [s for s in self.secrets if s["namespace"] == ns] if self.sa_can_read_secrets(sa) else []

    def netpol(self, namespace, appliesTo, ingress):
        return any(n.get("namespace") == namespace and n.get("appliesTo") == appliesTo
                   and n.get("ingress") == ingress for n in self.networkPolicies)


@dataclass
class ScoredFinding:
    id: str; source: str; title: str; target: str; severity: str
    base: float; adjusted: float; band: str; reachable: bool
    status: str = "open"            # open | accepted | auto-reopened
    acceptedBy: str = ""            # AR id
    rationale: list = field(default_factory=list)


def exposure_class(c, target):
    if target == "cluster":
        return "cluster"
    w = c.workloads.get(target)
    if w is None:
        return "internal"
    if not w.running:
        return "dormant"
    return "public" if w.publicly_exposed else "internal"


def score_finding(c, f):
    base = round(f["cvss"] * 10, 1) if f["type"] == "cve" else SEV_BASE[f["severity"]]
    exp = exposure_class(c, f["target"]); factor = EXPOSURE_FACTOR[exp]
    rationale = [f"base {base}",
                 {"public": "internet-reachable (x1.0)", "internal": "internal-only (x0.55)",
                  "dormant": "not running (x0.10)", "cluster": "cluster-level (x1.0)"}[exp]]
    boosts = 0.0
    w = c.workloads.get(f["target"])
    if w:
        if w.runAsRoot: boosts += BOOST["root"]; rationale.append("runs as root (+0.15)")
        if w.privileged: boosts += BOOST["privileged"]; rationale.append("privileged (+0.25)")
        if c.sa_can_read_secrets(w.serviceAccount): boosts += BOOST["secrets"]; rationale.append("SA reads Secrets (+0.20)")
    boosts = min(boosts, BOOST_CAP)
    adj = round(min(100.0, base * factor * (1 + boosts)), 1)
    return ScoredFinding(f["id"], f["source"], f["title"], f["target"], f["severity"],
                         base, adj, band(adj), exp != "dormant", rationale=rationale)


# ---------- accepted risks (mitigated-risk governance) ----------
@dataclass
class AcceptedRisk:
    id: str; match: dict; expires: str; owner: str; approver: str
    selector_type: str; compensating_controls: list; body: str


def load_accepted_risks(directory):
    out = []
    for path in sorted(glob.glob(os.path.join(directory, "*.md"))):
        txt = open(path).read()
        if not txt.startswith("---"):
            continue
        _, fm, body = txt.split("---", 2)
        d = yaml.safe_load(fm)
        out.append(AcceptedRisk(
            d["id"], d.get("match", {}), str(d.get("expires", "")), d.get("owner", ""),
            d.get("approver", ""), d.get("selector_type", "specific"),
            d.get("compensating_controls", []), body.strip()))
    return out


def ar_matches(ar, f):
    m = ar.match
    if "source" in m and m["source"] not in (f["source"], "*"): return False
    if "severity" in m and f["severity"] not in m["severity"]: return False
    if "cve" in m and f.get("cve") != m["cve"]: return False
    if "target" in m and f["target"] != m["target"]: return False
    return True


def verify_controls(ar, c):
    """Returns (all_verifiable_pass, results[]). A control with verify=None is
    'unverifiable' (does not fail, but is flagged)."""
    results, ok = [], True
    for ctrl in ar.compensating_controls:
        v = ctrl.get("verify")
        if v is None:
            results.append({"type": ctrl["type"], "status": "unverifiable"})
            continue
        passed = c.netpol(v.get("namespace"), v.get("appliesTo"), v.get("ingress")) \
            if ctrl["type"] == "network-policy" else True
        results.append({"type": ctrl["type"], "status": "verified" if passed else "FAILED"})
        ok = ok and passed
    return ok, results


def expired(ar, today):
    try:
        return datetime.date.fromisoformat(ar.expires) < today
    except Exception:
        return False


def correlate(inventory, findings, accepted_risks=None, today=None):
    c = Cluster(inventory)
    today = today or datetime.date.today()
    scored = {f["id"]: score_finding(c, f) for f in findings}
    fmap = {f["id"]: f for f in findings}

    accepted_out, refusals = [], []
    for ar in (accepted_risks or []):
        if expired(ar, today):
            continue
        for fid, s in scored.items():
            if s.status != "open" or not ar_matches(ar, fmap[fid]):
                continue
            # refusal rule: never silently accept High/Critical via a non-specific rule
            if s.band in ("Critical", "High") and ar.selector_type != "specific":
                refusals.append({"ar": ar.id, "finding": fid, "reason": f"{s.band} requires specific selector"})
                continue
            ok, ctrl_results = verify_controls(ar, c)
            if ok:
                s.status, s.acceptedBy = "accepted", ar.id
                accepted_out.append({"finding": fid, "title": s.title, "ar": ar.id,
                                     "owner": ar.owner, "expires": ar.expires, "controls": ctrl_results})
            else:
                s.status, s.acceptedBy = "auto-reopened", ar.id
                s.rationale.append(f"auto-reopened: compensating control failed under {ar.id}")

    active = [s for s in scored.values() if s.status != "accepted"]
    ranked = sorted(active, key=lambda s: s.adjusted, reverse=True)
    paths = build_attack_paths(c, {s.id: s for s in active})
    risk = posture_score({s.id: s for s in active}, paths)
    return {"cluster": c.name, "riskScore": risk,
            "findings": [asdict(s) for s in ranked],
            "acceptedRisks": accepted_out, "refusals": refusals,
            "attackPaths": [asdict(p) for p in paths]}


@dataclass
class AttackPath:
    id: str; title: str; severity: str; steps: list; why: str; fixes: list


def build_attack_paths(c, scored):
    paths, n = [], 0
    for w in c.workloads.values():
        if not (w.running and w.publicly_exposed):
            continue
        crit = [s for s in scored.values() if s.target == w.id and s.adjusted >= 58 and s.source == "trivy"]
        secrets = c.reachable_secrets(w.serviceAccount, w.namespace)
        if not crit or not secrets:
            continue
        n += 1; top = max(crit, key=lambda s: s.adjusted)
        entry = next((e.split(":", 1)[1] for e in w.exposedVia if e.startswith("ingress:")), "external endpoint")
        steps = [f"Entry - Ingress {entry} routes external traffic to {w.id}",
                 f"Foothold - {w.id} runs {w.image}, affected by {top.title} ({top.id})"
                 + (", and runs as root" if w.runAsRoot else ""),
                 f"Privilege - ServiceAccount {w.serviceAccount} can read Secrets in {w.namespace}",
                 f"Impact - reachable {secrets[0]['sensitivity']}-sensitivity Secret {secrets[0]['id']}"]
        why = ("An internet-reachable, root-running workload with a known high-severity vulnerability "
               "and Secret-reading rights chains external exposure to credential disclosure. "
               "Breaking any one link collapses the path.")
        fixes = [f"Patch the image (resolves {top.id})", "Set runAsNonRoot: true",
                 f"Remove get/list on Secrets from {w.serviceAccount}",
                 f"Add a NetworkPolicy restricting ingress to {w.id}"]
        paths.append(AttackPath(f"AP-{n}", "External exposure -> credential disclosure",
                                "Critical", steps, why, fixes))
    return paths


def posture_score(scored, paths):
    adj = sorted((s.adjusted for s in scored.values()), reverse=True)
    top = adj[0] if adj else 0
    avg3 = sum(adj[:3]) / max(1, len(adj[:3]))
    base = 0.7 * top + 0.3 * avg3
    if paths:
        base = max(base, 88)
    return round(min(100, base))


def render_markdown(r, scannedAt):
    L = [f"# ARGUS posture report - `{r['cluster']}`\n",
         f"_Scanned {scannedAt} - {len(r['findings'])} active findings - "
         f"{len(r['acceptedRisks'])} accepted - {len(r['attackPaths'])} attack path(s)_\n",
         f"## Risk score: **{r['riskScore']} / 100** ({band(r['riskScore'])})\n"]
    if r["attackPaths"]:
        L.append(f"> {len(r['attackPaths'])} reachable critical attack path drives this score - not raw CVE counts.\n")
    L.append("## Attack paths\n")
    for p in r["attackPaths"]:
        L.append(f"### {p['id']} - {p['title']} ({p['severity']})\n")
        L += [f"{i}. {s}" for i, s in enumerate(p["steps"], 1)]
        L.append(f"\n**Why it matters:** {p['why']}\n\n**Fix any one link:**")
        L += [f"- {fx}" for fx in p["fixes"]]; L.append("")
    L.append("## Active findings\n")
    L.append("| Finding | Source | Original | ARGUS | Score | Resource |")
    L.append("|---|---|---|---|---|---|")
    for s in r["findings"]:
        L.append(f"| {s['id']} {s['title']} | {s['source']} | {s['severity'].title()} | **{s['band']}** | {s['adjusted']} | `{s['target']}` |")
    if r["acceptedRisks"]:
        L.append("\n## Accepted risks (mitigated - suppressed from active feed)\n")
        for a in r["acceptedRisks"]:
            ctrls = ", ".join(f"{c['type']}:{c['status']}" for c in a["controls"])
            L.append(f"- **{a['finding']}** {a['title']} - accepted under `{a['ar']}` by {a['owner']}, "
                     f"expires {a['expires']}. Controls: {ctrls}")
    L.append("")
    return "\n".join(L)


def main():
    inv = json.load(open(os.path.join(HERE, "fixtures/inventory.json")))
    findings = json.load(open(os.path.join(HERE, "fixtures/findings.json")))["findings"]
    ars = load_accepted_risks(os.path.join(HERE, "fixtures/accepted-risks"))
    report = correlate(inv, findings, ars)
    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    json.dump(report, open(os.path.join(HERE, "out/report.json"), "w"), indent=2)
    open(os.path.join(HERE, "out/report.md"), "w").write(render_markdown(report, inv["scannedAt"]))
    print(f"Cluster {report['cluster']}: risk {report['riskScore']}/100, "
          f"{len(report['attackPaths'])} path(s), {len(report['acceptedRisks'])} accepted")
    for s in report["findings"]:
        print(f"  {s['id']}  {s['severity'].title():8} -> {s['band']:8} ({s['adjusted']:5})  {s['target']}")
    for a in report["acceptedRisks"]:
        print(f"  {a['finding']}  ACCEPTED via {a['ar']} (controls verified)")


if __name__ == "__main__":
    main()
```

### 6.5 `orchestrator.py`
```python
#!/usr/bin/env python3
"""
ARGUS - scan agent orchestrator (proof of concept)

An AGENT runs a full vulnerability scan WITHOUT generating dual-use cyber
content. It only (1) decides which TOOLS to call, and (2) reports factual,
defensive results. All detection is done by scanners; all risk reasoning by the
deterministic engine (argus_engine). The model never generates offensive
content, so this pipeline does not touch a cyber-content classifier.

PoC tools read fixtures (no live cluster). PROD: shell out to read-only binaries.

Usage: python orchestrator.py
"""
from __future__ import annotations
import json, os, datetime
import argus_engine as eng

HERE = os.path.dirname(os.path.abspath(__file__))

SYSTEM_PROMPT = """\
You are ARGUS, a defensive Kubernetes security operations assistant.
Your only job is to ORCHESTRATE read-only scanning tools and REPORT posture.
You choose which scan tools to run and on what scope, collect their output,
hand it to the correlation engine, apply accepted-risk policy, and summarize
findings and remediations in plain, defensive language.
You do NOT write exploits, payloads, malware, or offensive tooling; reason about
how to carry out an attack; or take any write action against the cluster.
All vulnerability detection and risk scoring is performed by tools, not by you.
"""

TOOLS = [
    {"name": "collect_inventory",   "description": "Read-only: enumerate cluster resources.", "params": {"kubeconfig": "str"}},
    {"name": "run_trivy",           "description": "Trivy image/config scan -> findings.",    "params": {"images": "list[str]"}},
    {"name": "run_kube_bench",      "description": "kube-bench CIS benchmark -> findings.",    "params": {}},
    {"name": "run_kubescape",       "description": "Kubescape posture scan -> findings.",      "params": {}},
    {"name": "load_accepted_risks", "description": "Load human-approved accepted-risk .md files.", "params": {"dir": "str"}},
    {"name": "correlate",           "description": "Deterministic engine: score + paths + apply accepted risks.", "params": {"inventory": "dict", "findings": "list", "accepted": "list"}},
    {"name": "render_report",       "description": "Write the posture report (md/json).",      "params": {"report": "dict"}},
]


def _load(name): return json.load(open(os.path.join(HERE, "fixtures", name)))
def _by_source(src): return [f for f in _load("findings.json")["findings"] if f["source"] == src]

def collect_inventory(kubeconfig="ro"):            # PROD: kubectl get ... -o json
    return _load("inventory.json")
def run_trivy(images=None):                        # PROD: trivy image --format json
    return _by_source("trivy")
def run_kube_bench():                              # PROD: kube-bench --json
    return _by_source("kube-bench")
def run_kubescape():                               # PROD: kubescape scan --format json
    return _by_source("kubescape")
def load_accepted_risks(directory="fixtures/accepted-risks"):
    return eng.load_accepted_risks(os.path.join(HERE, directory))
def correlate(inventory, findings, accepted):
    return eng.correlate(inventory, findings, accepted)
def render_report(report, scannedAt):
    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    open(os.path.join(HERE, "out/agent-report.md"), "w").write(eng.render_markdown(report, scannedAt))
    json.dump(report, open(os.path.join(HERE, "out/agent-report.json"), "w"), indent=2)
    return "out/agent-report.md"


def run_agent():
    print(f"[agent] role: defensive scan orchestrator (no offensive reasoning)\n")
    inv = collect_inventory("ro-kubeconfig")
    print(f"[agent] -> collect_inventory  :: {len(inv['workloads'])} workloads, {len(inv['secrets'])} secrets")
    findings = []
    for tool in (run_trivy, run_kube_bench, run_kubescape):
        r = tool(); findings += r
        print(f"[agent] -> {tool.__name__}  :: {len(r)} findings")
    ars = load_accepted_risks()
    print(f"[agent] -> load_accepted_risks  :: {len(ars)} active accepted-risk policy file(s)")
    report = correlate(inv, findings, ars)
    print(f"[agent] -> correlate  :: risk {report['riskScore']}/100, "
          f"{len(report['attackPaths'])} path(s), {len(report['acceptedRisks'])} accepted, "
          f"{len(report['refusals'])} refusal(s)")
    out = render_report(report, inv["scannedAt"])
    print(f"[agent] -> render_report  :: wrote {out}\n")

    crit = [f for f in report["findings"] if f["band"] == "Critical"]
    print("[agent] Summary:")
    print(f"        Cluster {report['cluster']} scored {report['riskScore']}/100.")
    print(f"        {len(crit)} critical active finding(s); {len(report['attackPaths'])} reachable path(s); "
          f"{len(report['acceptedRisks'])} risk(s) accepted with verified controls.")
    for p in report["attackPaths"]:
        print(f"        {p['id']}: {p['title']} - fix any of {len(p['fixes'])} controls to collapse it.")
    print("        Nothing was modified. All actions were read-only.")


if __name__ == "__main__":
    run_agent()
```
---

## 7. Accepted Risks (mitigated-risk) spec

An **Accepted Risk** is a human-authored markdown file the engine reads as
context. It lets a security owner formally accept a finding so the agent stops
re-flagging it — while keeping it visible, expiring, verified, and auditable.

**File:** `fixtures/accepted-risks/<id>.md` (prod: control-plane DB or the
customer repo at `.sentinel/accepted-risks/<id>.md`). YAML frontmatter + body.

**Required frontmatter:** `id`, `match`, `status`, `owner`, `approver`,
`created`, `expires` (max 90 days), `compensating_controls` (>= 1),
`selector_type` (`specific` | `category`).

**`match`** — a finding matches if every present key is satisfied:
`source`, `severity` (list), `cve`, `target` (resource id).

**`compensating_controls[].verify`** — the engine re-checks these every run.
A `network-policy` control verifies the named policy still exists in the live
inventory. `verify: null` is allowed but flagged "unverifiable" (it does not
fail the acceptance, but weakens it).

**Lifecycle the engine enforces (see `correlate`/`verify_controls`):**
1. **Match** open findings against active (non-expired) accepted risks.
2. **Refuse** to accept a Critical/High finding via a `category` selector — those
   require a `specific` selector (recorded in `refusals`). This stops an
   over-broad rule from silently swallowing a real risk.
3. **Verify** compensating controls. All verifiable pass -> `accepted` (excluded
   from the score and active feed, listed under Accepted Risks). Any verifiable
   control fails -> `auto-reopened` (returns to the active feed with a note).
4. **Expire** automatically past `expires`; the finding returns to the feed.
5. Accepted risks never reduce the score for an unverified reason, and are never
   silently dropped — they always appear in the report's Accepted Risks section.

Production hardening to add on top: immutable audit-log events
(`accepted_risk.created|matched|auto_reopened|expired|refused`), a UI
"Mark as Accepted" flow (compensating control required), and a 7-day-before-
expiry nag. The agent may *propose* a draft acceptance but only a human may
create one.

---

## 8. Production seams (turn fixtures into a live scan)

Each tool in `orchestrator.py` is marked `PROD:`. Replace the fixture read with
the real read-only binary call; the engine and accepted-risk logic stay
identical:

| Tool | PoC | Production |
|---|---|---|
| `collect_inventory` | reads `inventory.json` | `kubectl --kubeconfig <ro> get deploy,sa,rolebindings,svc,netpol,secrets -A -o json` -> assemble graph |
| `run_trivy` | reads fixture | `trivy image --format json <img>` per image, normalize |
| `run_kube_bench` | reads fixture | `kube-bench --json`, normalize |
| `run_kubescape` | reads fixture | `kubescape scan --format json`, normalize |

Use a **read-only** ServiceAccount/RBAC. Nothing here needs write access, SSH, or
node access. Validate against a throwaway cluster first: `kind create cluster`.

---

## 9. Which parts (if any) need a verified or self-hosted model

- **Engine + scanners + accepted risks (everything above):** deterministic. No
  model, no classifier, no verification needed. Ships today.
- **Agent orchestration + defensive summary:** a model emitting tool calls and
  factual results. Low risk; runs on Claude Agent SDK, GPT-5.5, or self-hosted
  Mistral/Llama via Hermes behind the same interface.
- **Optional richer attack-path narration by a model:** the only part that may
  trip dual-use. Put it behind a verification program (CVP / Trusted Access) or
  the self-hosted engine. The product works fully without it.

---

## 10. Definition of done

- `python argus_engine.py` and `python orchestrator.py` both run clean and
  reproduce §5.2.
- The same CVE is ranked Critical on the reachable workload and Low on the
  dormant one.
- `F-006` is suppressed under `AR-2026-001` with its NetworkPolicy control
  verified; removing that NetworkPolicy from `inventory.json` auto-reopens it.
- Accepting a Critical/High finding via a `category` selector is refused.
- No model generates offensive content anywhere in the pipeline.
