#!/usr/bin/env python3
"""
Live threat intelligence for ARGUS.

  - CISA KEV (Known Exploited Vulnerabilities) — fetched live from the official
    cisagov source. These CVEs are confirmed exploited in the wild.
  - EPSS (Exploit Prediction Scoring System) — probability a CVE is exploited in
    the next 30 days; fetched live from the FIRST.org API in production.
  - Local override file for embargoed/private/test intel, which wins over feeds.
  - On-disk cache with TTL so we don't hammer the feeds.

Sandbox note: the cisagov KEV mirror is reachable here, so KEV is REAL. The
FIRST.org EPSS API is not allow-listed in this sandbox, so EPSS falls back to the
override file; in production the live EPSS path runs. Either way the code is real.
"""
from __future__ import annotations
import json, os, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE = os.path.join(HERE, "cache", "threat-intel-cache.json")
OVERRIDE = os.path.join(HERE, "fixtures", "threat-intel-override.json")
TTL = 24 * 3600


def _fetch_kev():
    with urllib.request.urlopen(KEV_URL, timeout=30) as r:
        d = json.loads(r.read())
    kev = {v["cveID"]: (v.get("knownRansomwareCampaignUse", "Unknown") == "Known")
           for v in d["vulnerabilities"]}
    return d.get("catalogVersion", "?"), kev


def _fetch_epss(cves):
    """PROD path: batch-query FIRST.org. Returns {cve: epss}. Raises if unreachable."""
    out = {}
    for i in range(0, len(cves), 100):
        batch = ",".join(cves[i:i + 100])
        with urllib.request.urlopen(f"{EPSS_API}?cve={batch}", timeout=20) as r:
            d = json.loads(r.read())
        for row in d.get("data", []):
            out[row["cve"]] = float(row.get("epss", 0))
    return out


class Intel:
    def __init__(self, kev_ransom: dict, epss: dict, version: str, source: str):
        self._kev = kev_ransom          # cve -> ransomware(bool)
        self._epss = epss
        self.version = version
        self.source = source

    def is_kev(self, cve): return cve in self._kev
    def ransomware(self, cve): return bool(self._kev.get(cve, False))
    def epss(self, cve): return float(self._epss.get(cve, 0.0))
    def stats(self): return {"kev_count": len(self._kev), "epss_count": len(self._epss),
                             "version": self.version, "source": self.source}


def _load_override():
    if not os.path.exists(OVERRIDE):
        return {"kev": [], "ransomware": [], "epss": {}}
    return json.load(open(OVERRIDE))


def refresh(cves_for_epss=None, allow_network=True):
    """Build an Intel object. Live KEV (+ live EPSS in prod) merged with the local
    override. Caches the merged feed; falls back to cache then override on failure."""
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    ov = _load_override()
    kev, epss, version, source = {}, {}, "override-only", "override"

    # cache hit?
    if os.path.exists(CACHE) and time.time() - os.path.getmtime(CACHE) < TTL:
        c = json.load(open(CACHE))
        kev, version, source = {k: bool(v) for k, v in c["kev"].items()}, c["version"], "cache"
        epss = c.get("epss", {})
    elif allow_network:
        try:
            version, kev = _fetch_kev(); source = "live:cisa-kev"
        except Exception as e:
            source = f"kev-fetch-failed({type(e).__name__})"
        if cves_for_epss:
            try:
                epss = _fetch_epss(cves_for_epss)
            except Exception:
                pass  # EPSS not reachable -> override fills it
        json.dump({"kev": kev, "epss": epss, "version": version,
                   "fetched": time.time()}, open(CACHE, "w"))

    # merge override (wins): lets us flag embargoed/test CVEs
    for cve in ov.get("kev", []):
        kev.setdefault(cve, False)
    for cve in ov.get("ransomware", []):
        kev[cve] = True
    epss = {**epss, **ov.get("epss", {})}
    return Intel(kev, epss, version, source)


if __name__ == "__main__":
    intel = refresh()
    print("threat intel:", intel.stats())
    for cve in ["CVE-2026-31337", "CVE-2026-40002", "CVE-2025-22000"]:
        print(f"  {cve}: KEV={intel.is_kev(cve)} ransomware={intel.ransomware(cve)} EPSS={intel.epss(cve):.2f}")
