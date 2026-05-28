#!/usr/bin/env python3
"""
ARGUS engine v3 — CISO-grade attack-graph correlation.

New vs v2:
  - LIVE threat intel (threat_intel.py: real CISA KEV + EPSS + ransomware flag).
  - NETWORK-POLICY-AWARE lateral movement: a foothold can move to any
    network-reachable workload that is itself exploitable -> turns "latent" risk
    into "reachable" when no NetworkPolicy isolates it.
  - CLOUD-IAM DEPTH: ServiceAccount -> cloud role -> cloud data / assume-role ->
    cloud-admin (privilege escalation inside the cloud account).
  - CALIBRATABLE scoring (weights.json) + a CONFIDENCE rating per finding
    (lower when reachability is inferred from an absent control).
  - SCALE: choke-point analysis only re-tests control edges that lie on a path to
    a crown jewel (candidate pruning), not every edge.

Deterministic, auditable, no model in the loop.
Run: python engine.py  ->  out/report.md, out/report.json
"""
from __future__ import annotations
import json, os
from collections import deque, defaultdict

# Dual-import: works as ``python engine.py`` (script) and as
# ``from argus.engine_v3 import engine`` (package).
try:
    from . import threat_intel
except ImportError:                                          # script mode
    import threat_intel

HERE = os.path.dirname(os.path.abspath(__file__))
EXTERNAL, CADMIN, CLOUDADMIN = "ext:internet", "CLUSTER-ADMIN", "CLOUD-ADMIN"
W = json.load(open(os.path.join(HERE, "weights.json")))


# ---- RBAC danger classification --------------------------------------------
def _hit(rule, verbs, resources):
    return (set(rule["verbs"]) & (set(verbs) | {"*"})) and (set(rule["resources"]) & (set(resources) | {"*"}))

def sa_reads_secrets(sa): return any(_hit(r, ["get", "list", "watch"], ["secrets"]) for r in sa["rules"])

def sa_escalates(sa):
    for r in sa["rules"]:
        if _hit(r, ["create"], ["pods", "pods/exec", "deployments", "daemonsets"]): return True
        if _hit(r, ["create"], ["serviceaccounts/token"]): return True
        if _hit(r, ["create", "update", "patch"], ["clusterrolebindings", "rolebindings"]): return True
        if set(r["verbs"]) & {"escalate", "bind", "impersonate", "*"}: return True
    return False


# ---- graph -----------------------------------------------------------------
def ckey(c): return json.dumps(c, sort_keys=True) if c else None

class Graph:
    def __init__(self): self.e = defaultdict(list)        # src -> [(dst,label,control,inferred)]
    def add(self, s, d, label, control=None, inferred=False): self.e[s].append((d, label, control, inferred))
    def nbrs(self, n, skip=None): return [t for t in self.e[n] if skip is None or ckey(t[2]) != skip]
    def reachable(self, start, skip=None):
        seen, q = {start}, deque([start])
        while q:
            for d, _, _, _ in self.nbrs(q.popleft(), skip):
                if d not in seen: seen.add(d); q.append(d)
        return seen
    def path(self, start, target):
        prev, q = {start: None}, deque([start])
        while q:
            cur = q.popleft()
            if cur == target: break
            for d, l, c, inf in self.nbrs(cur):
                if d not in prev: prev[d] = (cur, l, c, inf); q.append(d)
        if target not in prev: return None
        out, cur = [], target
        while prev[cur] is not None:
            p, l, c, inf = prev[cur]; out.append((p, cur, l, c, inf)); cur = p
        return list(reversed(out))


def viable_cve(findings, intel):
    best = None
    for f in findings:
        if f["type"] != "cve": continue
        kev, epss = intel.is_kev(f["cve"]), intel.epss(f["cve"])
        if kev or epss >= 0.30 or f.get("cvss", 0) >= 9.0:
            rank = (1 if kev else 0, epss, f.get("cvss", 0))
            if best is None or rank > best[0]: best = (rank, f)
    return best[1] if best else None


def lateral_blocked(wl, netpols):
    for n in netpols:
        if n["namespace"] == wl["namespace"] and n.get("appliesTo") in (wl["id"].split("/")[1], "*") \
           and n.get("mode") == "deny-all":
            return True
    return False


def build(inv, findings, intel):
    g = Graph()
    wls = {w["id"]: w for w in inv["workloads"]}
    by_t = defaultdict(list)
    for f in findings: by_t[f["target"]].append(f)
    roles = {r["arn"]: r for r in inv.get("cloudRoles", [])}
    jewels = {CADMIN, CLOUDADMIN}
    for s in inv["secrets"]:
        if s["sensitivity"] == "high": jewels.add("secret:" + s["id"])

    compromisable = {}   # wl id -> viable cve finding
    for w in inv["workloads"]:
        if not w["running"]: continue
        fc = viable_cve(by_t[w["id"]], intel)
        if fc: compromisable[w["id"]] = fc

    for w in inv["workloads"]:
        wid = "wl:" + w["id"]
        if not w["running"]: continue
        fc = compromisable.get(w["id"])
        publicly = any(e.startswith(("ingress:", "loadbalancer:")) for e in w["exposedVia"])
        if fc and publicly:
            g.add(EXTERNAL, wid, f"exploit {fc['cve']} (internet-exposed)",
                  {"type": "patch", "ref": fc["cve"], "workload": w["id"]})
        g.add(wid, "sa:" + w["serviceAccount"], "uses ServiceAccount token")
        if w["privileged"] or w["hostPath"] or w["hostPID"] or "SYS_ADMIN" in w["capabilities"]:
            g.add(wid, "node:" + w["node"], "container escape -> node",
                  {"type": "harden-securitycontext", "workload": w["id"]})
        # lateral movement: to any OTHER network-reachable, exploitable workload
        for other_id, ofc in compromisable.items():
            if other_id == w["id"]: continue
            if not lateral_blocked(wls[other_id], inv["networkPolicies"]):
                g.add(wid, "wl:" + other_id,
                      f"lateral movement (network-reachable, {other_id} exploitable via {ofc['cve']})",
                      {"type": "network-isolate", "workload": other_id}, inferred=True)

    for s in inv["serviceAccounts"]:
        sid = "sa:" + s["id"]; ns = s["id"].split("/")[0]
        if sa_reads_secrets(s):
            for sec in inv["secrets"]:
                if sec["namespace"] == ns:
                    g.add(sid, "secret:" + sec["id"], "RBAC: can read Secret",
                          {"type": "rbac-least-privilege", "sa": s["id"], "what": "secrets"})
        if sa_escalates(s):
            g.add(sid, CADMIN, "RBAC: create/exec pods -> mount any SA -> cluster-admin",
                  {"type": "rbac-least-privilege", "sa": s["id"], "what": "escalation"})
        if s["cloudIdentity"]:
            g.add(sid, "crole:" + s["cloudIdentity"], "cloud workload identity",
                  {"type": "scope-cloud-identity", "sa": s["id"]})

    for r in inv.get("cloudRoles", []):
        rid = "crole:" + r["arn"]
        if r.get("admin"): g.add(rid, CLOUDADMIN, "cloud role is admin")
        for p in r.get("permissions", []):
            if p != "*:*":
                tgt = "clouddata:" + p; jewels.add(tgt)
                g.add(rid, tgt, f"cloud permission {p}")
        for tgt_arn in r.get("canAssume", []):
            if roles.get(tgt_arn, {}).get("admin"):
                g.add(rid, CLOUDADMIN, "sts:AssumeRole -> admin role (privilege escalation)",
                      {"type": "restrict-assume-role", "role": r["arn"]})
            else:
                g.add(rid, "crole:" + tgt_arn, "sts:AssumeRole")

    for n in inv["nodes"]:
        g.add("node:" + n["id"], CADMIN, "node compromise -> kubelet creds -> cluster-admin")
    return g, jewels, compromisable, wls


# ---- analysis --------------------------------------------------------------
def ssvc(open_, kev, epss, reaches_jewel, reaches_admin):
    likely = kev or epss >= W["ssvc"]["epss_likely"]
    if kev and open_ and reaches_jewel: return "Act"
    if open_ and reaches_admin: return "Act"
    if likely and (reaches_jewel or reaches_admin): return "Attend"
    if open_: return "Track"
    return "Track*"

def score(kev, epss, cvss, exposure, jewels_hit, admins_hit):
    threat = 1.0 if kev else max(epss, (cvss / 10.0) * W["cvss_fallback_factor"])
    expf = W["exposure"][exposure]
    impact = W["impact"]["base"] + sum(W["impact"][k] for k in jewels_hit) + sum(W["impact"][k] for k in admins_hit)
    return round(min(100, 100 * threat * expf * min(1.0, impact)))

def analyse(inv, findings, intel):
    g, jewels, compromisable, wls = build(inv, findings, intel)
    ext = g.reachable(EXTERNAL)
    reachable_jewels = [j for j in jewels if j in ext]
    paths = {j: g.path(EXTERNAL, j) for j in reachable_jewels}

    # candidate controls = those on a crown-jewel path (pruning for scale)
    cand = {}
    for p in paths.values():
        for _, _, _, c, _ in (p or []):
            if c: cand[ckey(c)] = c
    chokes = []
    for k, c in cand.items():
        wo = g.reachable(EXTERNAL, skip=k)
        broken = [j for j in reachable_jewels if j not in wo]
        if broken: chokes.append({"control": c, "breaks": len(broken), "targets": broken})
    chokes.sort(key=lambda x: -x["breaks"])

    scored = []
    for f in findings:
        if f["type"] != "cve": continue
        kev, epss = intel.is_kev(f["cve"]), intel.epss(f["cve"])
        wid = "wl:" + f["target"]
        nr = g.reachable(wid)
        jh = ([ "secret" ] if any(x.startswith("secret:") for x in nr) else []) + \
             (["cloud_data"] if any(x.startswith("clouddata:") for x in nr) else [])
        ah = (["cluster_admin"] if CADMIN in nr else []) + (["cloud_admin"] if CLOUDADMIN in nr else [])
        open_ = wid in ext
        comp = f["target"] in compromisable
        exposure = "open" if open_ else ("internal" if (wls.get(f["target"], {}).get("running") and comp) else "small")
        # confidence: did external reach this workload only via an inferred (lateral) edge?
        p = g.path(EXTERNAL, wid)
        conf = "high"
        if p is None: conf = "n/a"
        elif any(inf for *_, inf in p): conf = "medium (reachability inferred from absent NetworkPolicy)"
        sev = score(kev, epss, f.get("cvss", 0), exposure, jh, ah)
        dec = ssvc(open_, kev, epss, bool(jh), bool(ah))
        scored.append({"id": f["id"], "cve": f["cve"], "title": f["title"], "target": f["target"],
                       "kev": kev, "ransomware": intel.ransomware(f["cve"]), "epss": epss, "cvss": f.get("cvss"),
                       "exposure": exposure, "confidence": conf, "decision": dec, "score": sev,
                       "reaches": jh + ah})
    scored.sort(key=lambda s: (-{"Act": 3, "Attend": 2, "Track": 1, "Track*": 0}[s["decision"]], -s["score"]))
    risk = max([s["score"] for s in scored] + [0])
    if reachable_jewels: risk = max(risk, 92)
    return {"cluster": inv["cluster"], "intel": intel.stats(), "riskScore": risk,
            "reachableJewels": reachable_jewels, "paths": paths, "chokePoints": chokes, "findings": scored}


# ---- render ----------------------------------------------------------------
def pretty(n):
    return (n.replace("ext:internet", "Internet").replace("wl:", "").replace("sa:", "SA ")
            .replace("secret:", "Secret ").replace("crole:", "CloudRole ").replace("clouddata:", "CloudData ")
            .replace("node:", "Node "))

def describe(c):
    return {"patch": f"Patch {c.get('ref')} on {c.get('workload')}",
            "rbac-least-privilege": f"Remove {c.get('what')} RBAC from {c.get('sa')}",
            "harden-securitycontext": f"Drop privileged/hostPath on {c.get('workload')}",
            "scope-cloud-identity": f"Scope/remove cloud identity on {c.get('sa')}",
            "restrict-assume-role": f"Restrict sts:AssumeRole on {c.get('role')}",
            "network-isolate": f"Add NetworkPolicy isolating {c.get('workload')}"}[c["type"]]

def render_md(r):
    s = r["intel"]
    L = [f"# ARGUS attack-graph report — `{r['cluster']}`\n",
         f"_Threat intel: {s['source']} · KEV catalog {s['version']} · {s['kev_count']} known-exploited CVEs_\n",
         f"## Posture risk: **{r['riskScore']}/100**\n",
         f"_{len(r['reachableJewels'])} crown-jewel target(s) an external attacker can reach today._\n",
         "## Do this first — choke-point analysis\n"]
    for i, ch in enumerate(r["chokePoints"], 1):
        L.append(f"{i}. **{describe(ch['control'])}** — eliminates **{ch['breaks']}** of "
                 f"{len(r['reachableJewels'])} active paths ({', '.join(pretty(t) for t in ch['targets'])})")
    L.append("\n## Active attack paths\n")
    for tgt, p in r["paths"].items():
        L.append(f"### → {pretty(tgt)}")
        for a, b, l, c, inf in p:
            tag = " _(inferred)_" if inf else ""
            L.append(f"- {pretty(a)} ==[{l}]==> {pretty(b)}{tag}")
        L.append("")
    L.append("## Findings — threat-intel + reachability prioritized\n")
    L.append("| ID | CVE | KEV | Ransom | EPSS | Exposure | Reaches | SSVC | Score | Confidence |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for f in r["findings"]:
        L.append(f"| {f['id']} {f['target']} | {f['cve']} | {'YES' if f['kev'] else '-'} | "
                 f"{'YES' if f['ransomware'] else '-'} | {f['epss']:.2f} | {f['exposure']} | "
                 f"{','.join(f['reaches']) or '-'} | **{f['decision']}** | {f['score']} | {f['confidence']} |")
    L.append("\n_KEV = CISA Known-Exploited (live). SSVC: Act>Attend>Track>Track*. "
             "Confidence drops when reachability depends on an absent control (e.g. no NetworkPolicy)._")
    return "\n".join(L)


def main():
    inv = json.load(open(os.path.join(HERE, "fixtures/inventory.json")))
    findings = json.load(open(os.path.join(HERE, "fixtures/findings.json")))["findings"]
    cves = [f["cve"] for f in findings if f.get("cve")]
    intel = threat_intel.refresh(cves_for_epss=cves)
    r = analyse(inv, findings, intel)
    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    json.dump(r, open(os.path.join(HERE, "out/report.json"), "w"), indent=2, default=str)
    open(os.path.join(HERE, "out/report.md"), "w").write(render_md(r))
    print(f"intel: {intel.stats()['source']} KEV={intel.stats()['kev_count']} (v{intel.stats()['version']})")
    print(f"risk {r['riskScore']}/100 | reachable crown jewels: {len(r['reachableJewels'])}")
    print("top fixes:")
    for ch in r["chokePoints"][:4]:
        print(f"  breaks {ch['breaks']}: {describe(ch['control'])}")
    print("findings:")
    for f in r["findings"]:
        print(f"  {f['id']:6} {f['cve']:16} {f['decision']:7} score={f['score']:3} "
              f"exp={f['exposure']:8} conf={f['confidence'][:6]}")
    return r


if __name__ == "__main__":
    main()
