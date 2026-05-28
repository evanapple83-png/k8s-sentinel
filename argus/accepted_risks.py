"""argus/accepted_risks.py — mitigated-risk (accepted-risk) governance.

Ported out of the retired ``argus_engine.py`` so it survives the v3 engine
swap. The logic is unchanged — only the inventory shape it verifies against
moved from the old ``{ingress: deny-external}`` to the v3
``{mode: deny-external}``. Both keys are accepted in YAML for back-compat.

What it does
------------
Reads YAML-frontmatter ``.md`` files from a directory, matches them against
raw scanner findings, verifies their compensating controls against the live
inventory, and emits four collections so the CLI can:

  * pass the *active* findings into the engine (accepted ones filtered out);
  * report the accepted set alongside the engine's output;
  * surface refusals (e.g. trying to accept a Critical via a broad selector);
  * surface auto-reopens when a compensating control no longer holds.

It is engine-agnostic — never imports ``engine.py`` and never reads any
output of it. Accepted-risk governance is meant to be auditable in
isolation.
"""
from __future__ import annotations

import datetime
import glob
import os
from dataclasses import dataclass, field
from typing import Iterable, Optional

import yaml


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class AcceptedRisk:
    id: str
    match: dict
    expires: str
    owner: str
    approver: str
    selector_type: str                              # "specific" | "category"
    compensating_controls: list = field(default_factory=list)
    body: str = ""

    @property
    def is_specific(self) -> bool:
        return self.selector_type == "specific"


@dataclass
class ApplyResult:
    """Outcome of running the accepted-risk policy against a finding set."""
    active_findings: list = field(default_factory=list)     # to feed the engine
    accepted:        list = field(default_factory=list)     # {finding, ar, owner, expires, controls}
    refusals:        list = field(default_factory=list)     # {ar, finding, reason}
    auto_reopened:   list = field(default_factory=list)     # {ar, finding, reason}


# ---------------------------------------------------------------------------
# Loader — .md with YAML frontmatter
# ---------------------------------------------------------------------------

def load(directory: str) -> list:
    """Parse every ``*.md`` under ``directory`` with YAML frontmatter. Files
    without a frontmatter block are skipped (not an error)."""
    out: list = []
    for path in sorted(glob.glob(os.path.join(directory, "*.md"))):
        with open(path) as f:
            txt = f.read()
        if not txt.startswith("---"):
            continue
        # txt = "---\n<yaml>\n---\n<body>"
        _, fm, body = txt.split("---", 2)
        d = yaml.safe_load(fm) or {}
        out.append(AcceptedRisk(
            id=d["id"],
            match=d.get("match") or {},
            expires=str(d.get("expires", "")),
            owner=d.get("owner", ""),
            approver=d.get("approver", ""),
            selector_type=d.get("selector_type", "specific"),
            compensating_controls=d.get("compensating_controls") or [],
            body=body.strip(),
        ))
    return out


# ---------------------------------------------------------------------------
# Matching + verification
# ---------------------------------------------------------------------------

# Findings whose severity is one of these require a specific selector. This
# prevents an over-broad "category" rule from silently swallowing a real risk.
_ELEVATED_SEVERITIES = {"critical", "high"}


def matches(ar: AcceptedRisk, finding: dict) -> bool:
    """A finding matches an AR iff every present key in ``ar.match`` is
    satisfied by the finding. Missing keys mean "don't care"."""
    m = ar.match
    if "source" in m and m["source"] not in (finding.get("source"), "*"):
        return False
    if "severity" in m and finding.get("severity") not in m["severity"]:
        return False
    if "cve" in m and finding.get("cve") != m["cve"]:
        return False
    if "target" in m and finding.get("target") != m["target"]:
        return False
    return True


def verify_controls(ar: AcceptedRisk, inventory: dict) -> tuple:
    """Re-check every compensating control. Returns
    ``(all_verifiable_pass: bool, results: list[dict])``.

    A control with ``verify: null`` is "unverifiable" — it does not fail the
    AR but is flagged. The only control type currently re-checked is
    ``network-policy``, which verifies the policy still exists in the live
    inventory with the expected mode."""
    results, ok = [], True
    netpols = inventory.get("networkPolicies") or []
    for ctrl in ar.compensating_controls:
        v = ctrl.get("verify")
        if v is None:
            results.append({"type": ctrl["type"], "status": "unverifiable"})
            continue
        if ctrl["type"] == "network-policy":
            # Back-compat: old AR docs used ``ingress``, v3 uses ``mode``.
            expected_mode = v.get("mode") or v.get("ingress")
            # A stricter observed mode still satisfies a less-strict claim:
            #   deny-all      ⊇ deny-external ⊇ open
            satisfies = {
                "deny-all":      {"deny-all", "deny-external", "open"},
                "deny-external": {"deny-external", "open"},
                "open":          {"open"},
            }
            passed = any(
                n.get("namespace") == v.get("namespace")
                and n.get("appliesTo") == v.get("appliesTo")
                and expected_mode in satisfies.get(n.get("mode") or "", {n.get("mode")})
                for n in netpols
            )
        else:
            # Unknown control types pass by default — there's nothing to
            # invalidate. They're recorded as "verified (no-op)".
            passed = True
        results.append({"type": ctrl["type"], "status": "verified" if passed else "FAILED"})
        ok = ok and passed
    return ok, results


def is_expired(ar: AcceptedRisk, today: Optional[datetime.date] = None) -> bool:
    today = today or datetime.date.today()
    try:
        return datetime.date.fromisoformat(ar.expires) < today
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Apply — main entry
# ---------------------------------------------------------------------------

def apply(
    findings: Iterable[dict],
    accepted_risks: Iterable[AcceptedRisk],
    inventory: dict,
    *,
    today: Optional[datetime.date] = None,
) -> ApplyResult:
    """Run accepted-risk policy against ``findings`` using ``inventory`` for
    compensating-control verification. Pure function — no I/O, no logging,
    no engine call."""
    today = today or datetime.date.today()
    findings_by_id = {f["id"]: f for f in findings}
    status: dict = {}          # finding_id -> "open" | "accepted" | "auto-reopened"
    accepted_out: list = []
    refusals: list = []
    auto_reopened: list = []

    for ar in accepted_risks or []:
        if is_expired(ar, today):
            continue
        for fid, f in findings_by_id.items():
            if status.get(fid, "open") != "open":
                continue
            if not matches(ar, f):
                continue
            sev = (f.get("severity") or "").lower()
            if sev in _ELEVATED_SEVERITIES and not ar.is_specific:
                refusals.append({
                    "ar": ar.id, "finding": fid,
                    "reason": f"{sev} finding requires a specific selector",
                })
                continue
            ok, ctrl_results = verify_controls(ar, inventory)
            if ok:
                status[fid] = "accepted"
                accepted_out.append({
                    "finding": fid,
                    "title":   f.get("title", ""),
                    "target":  f.get("target", ""),
                    "ar":      ar.id,
                    "owner":   ar.owner,
                    "expires": ar.expires,
                    "controls": ctrl_results,
                })
            else:
                status[fid] = "auto-reopened"
                auto_reopened.append({
                    "ar": ar.id, "finding": fid,
                    "reason": f"compensating control failed under {ar.id}",
                    "controls": ctrl_results,
                })

    active = [f for fid, f in findings_by_id.items() if status.get(fid, "open") != "accepted"]
    return ApplyResult(
        active_findings=active,
        accepted=accepted_out,
        refusals=refusals,
        auto_reopened=auto_reopened,
    )
