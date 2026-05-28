import json, os, engine, threat_intel
H = os.path.dirname(os.path.abspath(__file__))
inv = json.load(open(f"{H}/fixtures/inventory.json"))
fnd = json.load(open(f"{H}/fixtures/findings.json"))["findings"]
intel = threat_intel.refresh(cves_for_epss=[f["cve"] for f in fnd])
r = engine.analyse(inv, fnd, intel)
d = {f["id"]: f for f in r["findings"]}
assert len(r["reachableJewels"]) == 4, r["reachableJewels"]
assert d["F-001"]["decision"] == "Act" and d["F-001"]["score"] == 100, d["F-001"]
assert d["F-001"]["confidence"] == "high", d["F-001"]
assert d["F-009"]["decision"] == "Act" and d["F-009"]["exposure"] == "open", d["F-009"]
assert d["F-009"]["confidence"].startswith("medium"), d["F-009"]    # lateral = inferred
assert d["F-002"]["decision"] == "Track*", d["F-002"]
top = r["chokePoints"][0]
assert top["control"]["type"] == "patch" and top["breaks"] == 4, top
assert intel.stats()["kev_count"] > 1000, "live KEV not loaded"
print("ALL ASSERTIONS PASSED — v3 engine behaves to spec, live intel loaded.")
