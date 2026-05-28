"""unittest wrapper around ``argus/engine_v3/test_engine.py``.

The v3 engine's authoritative regression lives next to the engine
(``argus/engine_v3/test_engine.py``) so it's runnable as a script
(``python argus/engine_v3/test_engine.py``). This wrapper plumbs the same
assertions through unittest so ``python -m unittest discover -s argus/tests``
picks them up.

The wrapper hits the LIVE CISA KEV feed (the user explicitly authorised that
fetch). It does NOT hit FIRST.org EPSS — the override file fills those in.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from argus.engine_v3 import engine, threat_intel               # noqa: E402

ENGINE_DIR = os.path.join(REPO_ROOT, "argus", "engine_v3")


class EngineV3Regression(unittest.TestCase):
    """Mirror of ``argus/engine_v3/test_engine.py``. Hits live CISA KEV."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ENGINE_DIR, "fixtures", "inventory.json")) as f:
            inv = json.load(f)
        with open(os.path.join(ENGINE_DIR, "fixtures", "findings.json")) as f:
            findings = json.load(f)["findings"]
        intel = threat_intel.refresh(cves_for_epss=[f["cve"] for f in findings])
        cls.report = engine.analyse(inv, findings, intel)
        cls.intel = intel
        cls.by_id = {f["id"]: f for f in cls.report["findings"]}

    def test_live_kev_loaded(self):
        self.assertGreater(self.intel.stats()["kev_count"], 1000,
                           "live CISA KEV catalog should carry >1000 CVEs")

    def test_four_crown_jewels_reachable(self):
        self.assertEqual(len(self.report["reachableJewels"]), 4,
                         self.report["reachableJewels"])

    def test_f001_is_act_score_100_high_confidence(self):
        f = self.by_id["F-001"]
        self.assertEqual(f["decision"], "Act")
        self.assertEqual(f["score"], 100)
        self.assertEqual(f["confidence"], "high")

    def test_f009_is_act_with_inferred_lateral_confidence(self):
        f = self.by_id["F-009"]
        self.assertEqual(f["decision"], "Act")
        self.assertEqual(f["exposure"], "open")
        self.assertTrue(f["confidence"].startswith("medium"),
                        f"expected medium confidence (lateral inferred), got {f['confidence']}")

    def test_f002_dormant_clone_track_star(self):
        # Same CVE on a non-running workload — engine demotes to Track*.
        self.assertEqual(self.by_id["F-002"]["decision"], "Track*")

    def test_top_choke_point_breaks_four_jewels(self):
        top = self.report["chokePoints"][0]
        self.assertEqual(top["control"]["type"], "patch")
        self.assertEqual(top["breaks"], 4)


if __name__ == "__main__":
    unittest.main()
