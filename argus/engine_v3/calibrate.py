#!/usr/bin/env python3
"""
Calibration harness — tunes scoring/decision thresholds against LABELED scenarios
and reports accuracy. CISO-grade means decisions are calibrated, not hand-waved.

Method (real): a labeled corpus of (features -> expected SSVC decision); grid-search
the tunable threshold(s) to maximize agreement; write the calibrated weights.
Here the corpus is small + synthetic to demonstrate the METHOD. In production this
corpus is built from real triaged incidents / analyst decisions, and is far larger.
"""
import json, os, engine

# (kev, epss, cvss, exposure, reaches_jewel, reaches_admin, expected_decision)
LABELED = [
    (True,  0.92, 9.8, "open",     True,  True,  "Act"),
    (False, 0.61, 8.1, "open",     False, True,  "Act"),
    (False, 0.61, 8.1, "internal", True,  False, "Attend"),
    (False, 0.04, 5.3, "internal", False, False, "Track*"),
    (True,  0.92, 9.8, "small",    False, False, "Track*"),
    (False, 0.35, 7.0, "open",     True,  False, "Attend"),
    (False, 0.20, 6.0, "open",     False, False, "Track"),
    (False, 0.28, 6.5, "open",     True,  False, "Attend"),   # borderline: sensitive to threshold
]

def accuracy(epss_likely):
    orig = engine.W["ssvc"]["epss_likely"]
    engine.W["ssvc"]["epss_likely"] = epss_likely
    correct = sum(engine.ssvc(o, k, e, j, a) == exp
                  for (k, e, c, o, j, a, exp) in LABELED)
    engine.W["ssvc"]["epss_likely"] = orig
    return correct / len(LABELED)

def main():
    base = accuracy(engine.W["ssvc"]["epss_likely"])
    grid = [round(0.05 * i, 2) for i in range(1, 11)]   # 0.05 .. 0.50
    best_t, best_a = max(((t, accuracy(t)) for t in grid), key=lambda x: x[1])
    print(f"baseline epss_likely={engine.W['ssvc']['epss_likely']}  accuracy={base:.0%}")
    print(f"calibrated epss_likely={best_t}            accuracy={best_a:.0%}")
    # persist calibrated weights
    w = dict(engine.W); w["ssvc"] = dict(w["ssvc"]); w["ssvc"]["epss_likely"] = best_t
    json.dump(w, open(os.path.join(os.path.dirname(__file__), "weights.calibrated.json"), "w"), indent=2)
    print("wrote weights.calibrated.json")
    print("NOTE: synthetic corpus (8 cases) demonstrates the method; production needs a")
    print("      large corpus of real analyst-triaged decisions to be truly calibrated.")

if __name__ == "__main__":
    main()
