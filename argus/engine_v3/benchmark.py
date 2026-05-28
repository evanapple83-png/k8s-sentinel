#!/usr/bin/env python3
"""Scale benchmark — generate synthetic clusters of increasing size and time analyse()."""
import time, random, engine, threat_intel

def synth(n, seed=7):
    random.seed(seed)
    wls, sas, secrets, nps = [], [], [], []
    kev, epss = {}, {}
    for i in range(n):
        ns = f"ns{i % 50}"; sa = f"{ns}/sa{i}"
        exposed = (i % 23 == 0)                      # ~4% internet-exposed
        vuln = (i % 7 == 0)                          # ~14% carry a viable CVE
        cve = f"CVE-SYN-{i}"
        if vuln:
            epss[cve] = round(random.uniform(0.3, 0.95), 2)
            if i % 21 == 0: kev[cve] = True
        wls.append({"id": f"{ns}/w{i}", "namespace": ns, "running": True,
                    "image": f"img{i}:1.0", "serviceAccount": sa, "node": f"node{i%20}",
                    "runAsRoot": (i % 5 == 0), "privileged": (i % 200 == 0), "hostPath": [],
                    "hostPID": False, "capabilities": [], "exposedVia": (["ingress:h"] if exposed else [])})
        rules = [{"verbs": ["get"], "resources": ["secrets"], "scope": ns}] if i % 11 == 0 else []
        if i % 97 == 0: rules.append({"verbs": ["create"], "resources": ["pods/exec"], "scope": "*"})
        sas.append({"id": sa, "rules": rules, "cloudIdentity": None})
        if i % 11 == 0: secrets.append({"id": f"{ns}/s{i}", "namespace": ns, "sensitivity": "high"})
    findings = [{"id": f"F{i}", "source": "trivy", "type": "cve", "cve": f"CVE-SYN-{i}",
                 "cvss": 8.0, "severity": "high", "target": w["id"], "title": "synthetic"}
                for i, w in enumerate(wls) if i % 7 == 0]
    inv = {"cluster": f"synthetic-{n}", "scannedAt": "2026-05-28T00:00:00Z", "workloads": wls,
           "serviceAccounts": sas, "cloudRoles": [], "secrets": secrets,
           "nodes": [{"id": f"node{i}"} for i in range(20)], "networkPolicies": nps}
    intel = threat_intel.Intel(kev, epss, "synthetic", "synthetic")
    return inv, findings, intel

def main():
    print(f"{'workloads':>10} {'findings':>9} {'jewels':>7} {'seconds':>9}")
    for n in (100, 500, 1000, 2000):
        inv, findings, intel = synth(n)
        t = time.time(); r = engine.analyse(inv, findings, intel); dt = time.time() - t
        print(f"{n:>10} {len(findings):>9} {len(r['reachableJewels']):>7} {dt:>9.2f}")

if __name__ == "__main__":
    main()
