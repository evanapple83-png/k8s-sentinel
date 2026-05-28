"""argus/scanners.py — read-only scanner adapters.

Each adapter shells out to a single CLI binary (Trivy / kube-bench / Kubescape),
parses its JSON, and normalises to the engine's frozen **Finding** shape::

    { id, source, type, cve?, cvss?, ruleId?, severity, target, title }

Design contract
---------------
* **Read-only.** No write/patch/exec verbs. The adapters never invoke anything
  beyond the scanner binary and never look at Secret ``.data``.
* **Fail safe.** A missing binary or a non-zero exit is logged and the scanner
  is reported as ``skipped`` / ``errored``; the run never crashes. The CLI
  (Phase 3) surfaces the :class:`ScannerResult` list as report metadata so
  consumers can see which scanners actually ran.
* **Subprocess seam.** Every adapter accepts a ``runner`` argument matching the
  ``subprocess.run`` signature. Tests pass a fake runner returning canned JSON;
  production passes ``subprocess.run`` (the default).
* **Targets match inventory.** ``target`` on each Finding equals the
  ``"<ns>/<name>"`` id used in the Inventory's ``workloads[]``. For
  cluster-level checks (kube-bench) ``target`` is the literal string
  ``"cluster"``, matching the engine's ``exposure_class`` cluster path.
* **Scanner output is hostile input.** Titles are length-capped and stripped of
  control characters before they enter the report. This keeps the door shut
  for any downstream model context (Phase 9 / agent layer).
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

log = logging.getLogger(__name__)

# subprocess.run-shaped callable
Runner = Callable[..., subprocess.CompletedProcess]

# Max title length before we truncate. Long enough for any real scanner title,
# short enough to bound any downstream model context cost.
_MAX_TITLE = 240
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_TRIVY_SEVERITY = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "UNKNOWN": "low", "NEGLIGIBLE": "low",
}


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass
class ScannerResult:
    """Per-scanner run metadata. Surfaced in the final report so users can see
    *which* scanners contributed and which were unavailable."""
    name: str                          # "trivy" | "kube-bench" | "kubescape"
    status: str                        # "ran" | "skipped" | "errored"
    reason: str = ""                   # human-readable note
    findings_count: int = 0
    duration_ms: Optional[int] = None


@dataclass
class _Counter:
    """Deterministic ID source per scanner run."""
    source: str
    n: int = 0

    def next_id(self) -> str:
        self.n += 1
        return f"{self.source}-{self.n:03d}"


# ---------------------------------------------------------------------------
# Helpers shared by all adapters
# ---------------------------------------------------------------------------

def _sanitize_text(value: Any) -> str:
    """Coerce arbitrary scanner text into a bounded, control-char-free string.
    Scanner output is treated as hostile (per docs/argus-go-live-task.md §4)."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL_CHAR_RE.sub("", text)
    if len(text) > _MAX_TITLE:
        text = text[: _MAX_TITLE - 1].rstrip() + "…"
    return text


def _run_binary(runner: Runner, argv: list, *, scanner: str) -> tuple[Optional[str], ScannerResult]:
    """Invoke a scanner binary and return ``(stdout, ScannerResult)``. Returns
    ``(None, result)`` if the binary is missing or the call failed. The caller
    decides what to do with stdout."""
    if not shutil.which(argv[0]):
        msg = f"{scanner}: binary {argv[0]!r} not found on PATH"
        log.warning(msg)
        return None, ScannerResult(name=scanner, status="skipped", reason=msg)
    try:
        proc = runner(argv, capture_output=True, text=True, check=False, timeout=600)
    except FileNotFoundError as e:
        msg = f"{scanner}: binary disappeared after PATH check: {e}"
        log.warning(msg)
        return None, ScannerResult(name=scanner, status="skipped", reason=msg)
    except subprocess.TimeoutExpired:
        msg = f"{scanner}: timed out after 600s"
        log.warning(msg)
        return None, ScannerResult(name=scanner, status="errored", reason=msg)
    except Exception as e:                       # noqa: BLE001 — defensive guard
        msg = f"{scanner}: unexpected runner failure: {e}"
        log.warning(msg)
        return None, ScannerResult(name=scanner, status="errored", reason=msg)

    # Some scanners exit non-zero when findings exist (Trivy with --exit-code);
    # treat that as a successful run as long as stdout looks like JSON. We only
    # mark "errored" when stdout is empty.
    if proc.returncode != 0 and not (proc.stdout and proc.stdout.strip()):
        msg = f"{scanner}: exit {proc.returncode}; stderr={proc.stderr.strip()[:200]!r}"
        log.warning(msg)
        return None, ScannerResult(name=scanner, status="errored", reason=msg)

    return proc.stdout, ScannerResult(name=scanner, status="ran")


def _safe_json(scanner: str, blob: str) -> Optional[dict]:
    try:
        return json.loads(blob) if blob else None
    except json.JSONDecodeError as e:
        log.warning("%s: JSON parse failed at offset %d: %s", scanner, e.pos, e.msg)
        return None


def unique_images(workloads: Iterable[dict]) -> dict:
    """Return ``{image: [workload-id, ...]}`` from the Inventory's workloads.
    Same image used by multiple workloads → one scan, N findings per CVE
    (matches the PoC fixture where the dormant clone shares the vulnerable
    image)."""
    out: dict = {}
    for w in workloads:
        image = w.get("image") or ""
        if not image:
            continue
        out.setdefault(image, []).append(w["id"])
    return out


# ---------------------------------------------------------------------------
# Trivy — per-image CVE scan
# ---------------------------------------------------------------------------

def run_trivy(
    images_with_targets: dict,
    *,
    runner: Optional[Runner] = None,
    binary: str = "trivy",
) -> tuple[list, ScannerResult]:
    """Run ``trivy image --format json`` once per unique image and normalise
    every vulnerability into one Finding **per running workload** that uses
    that image."""
    runner = runner or subprocess.run
    counter = _Counter("trivy")
    findings: list = []

    if not images_with_targets:
        return findings, ScannerResult(name="trivy", status="skipped",
                                       reason="no images discovered in inventory",
                                       findings_count=0)

    binary_seen = False
    last_result: ScannerResult = ScannerResult(name="trivy", status="ran")
    for image, targets in sorted(images_with_targets.items()):
        argv = [binary, "image", "--quiet", "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW", image]
        stdout, result = _run_binary(runner, argv, scanner="trivy")
        if result.status == "skipped" and not binary_seen:
            # Binary not installed at all — short-circuit the whole adapter.
            return [], result
        binary_seen = True
        last_result = result
        if stdout is None:
            continue
        doc = _safe_json("trivy", stdout)
        if not isinstance(doc, dict):
            continue
        for entry in _trivy_vulns(doc, image, targets, counter):
            findings.append(entry)

    last_result.findings_count = len(findings)
    return findings, last_result


def _trivy_vulns(doc: dict, image: str, targets: list, counter: _Counter) -> Iterable[dict]:
    results = doc.get("Results") or []
    for res in results:
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            cve = v.get("VulnerabilityID") or ""
            sev = _TRIVY_SEVERITY.get((v.get("Severity") or "").upper())
            if sev is None or not cve:
                continue
            cvss_score = _trivy_cvss(v)
            title = _sanitize_text(v.get("Title") or v.get("Description") or cve)
            for target in targets:
                yield {
                    "id":       counter.next_id(),
                    "source":   "trivy",
                    "type":     "cve",
                    "cve":      cve,
                    "cvss":     cvss_score,
                    "severity": sev,
                    "target":   target,
                    "title":    title,
                    "image":    image,
                }


def _trivy_cvss(vuln: dict) -> float:
    cvss = vuln.get("CVSS") or {}
    best = 0.0
    for vendor in cvss.values():
        if not isinstance(vendor, dict):
            continue
        score = vendor.get("V3Score") or vendor.get("v3Score") or vendor.get("V2Score")
        try:
            score = float(score) if score is not None else 0.0
        except (TypeError, ValueError):
            score = 0.0
        best = max(best, score)
    return round(best, 1)


# ---------------------------------------------------------------------------
# kube-bench — CIS benchmark on control plane / nodes
# ---------------------------------------------------------------------------

def run_kube_bench(
    *,
    runner: Optional[Runner] = None,
    binary: str = "kube-bench",
    extra_args: Optional[list] = None,
) -> tuple[list, ScannerResult]:
    runner = runner or subprocess.run
    counter = _Counter("kube-bench")
    argv = [binary, "--json"] + list(extra_args or [])
    stdout, result = _run_binary(runner, argv, scanner="kube-bench")
    if stdout is None:
        return [], result

    doc = _safe_json("kube-bench", stdout)
    if not isinstance(doc, dict):
        result.status = "errored"
        result.reason = "kube-bench: stdout was not a JSON object"
        return [], result

    findings = list(_kube_bench_findings(doc, counter))
    result.findings_count = len(findings)
    return findings, result


def _kube_bench_findings(doc: dict, counter: _Counter) -> Iterable[dict]:
    for control in (doc.get("Controls") or [doc]):
        for test in (control.get("tests") or []):
            for r in (test.get("results") or []):
                status = (r.get("status") or "").upper()
                if status != "FAIL":
                    continue
                rule_id = _sanitize_text(r.get("test_number") or r.get("test_id") or "")
                title = _sanitize_text(r.get("test_desc") or rule_id or "kube-bench failure")
                yield {
                    "id":       counter.next_id(),
                    "source":   "kube-bench",
                    "type":     "cis",
                    "ruleId":   rule_id,
                    "severity": "medium",
                    "target":   "cluster",
                    "title":    title,
                }


# ---------------------------------------------------------------------------
# Kubescape — posture scan, failed controls → misconfig findings
# ---------------------------------------------------------------------------

def run_kubescape(
    *,
    runner: Optional[Runner] = None,
    binary: str = "kubescape",
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    framework: str = "nsa",
) -> tuple[list, ScannerResult]:
    runner = runner or subprocess.run
    counter = _Counter("kubescape")
    argv = [binary, "scan", "framework", framework,
            "--format", "json", "--format-version", "v2", "--output", "-"]
    if kubeconfig:
        argv += ["--kubeconfig", kubeconfig]
    if context:
        argv += ["--kube-context", context]
    stdout, result = _run_binary(runner, argv, scanner="kubescape")
    if stdout is None:
        return [], result

    doc = _safe_json("kubescape", stdout)
    if not isinstance(doc, dict):
        result.status = "errored"
        result.reason = "kubescape: stdout was not a JSON object"
        return [], result

    findings = list(_kubescape_findings(doc, counter))
    result.findings_count = len(findings)
    return findings, result


def _kubescape_findings(doc: dict, counter: _Counter) -> Iterable[dict]:
    summary_controls = (doc.get("summaryDetails") or {}).get("controls") or {}
    for entry in (doc.get("results") or []):
        target = _kubescape_target(entry.get("resourceID") or "")
        controls = entry.get("controls") or {}
        if isinstance(controls, dict):
            iterable = controls.values()
        else:
            iterable = controls  # some versions emit a list
        for ctrl in iterable:
            status = ((ctrl.get("status") or {}).get("status") or "").lower()
            if status != "failed":
                continue
            ctrl_id = _sanitize_text(ctrl.get("controlID") or "")
            name = _sanitize_text(ctrl.get("name") or ctrl_id or "kubescape failure")
            score = _kubescape_score(ctrl, summary_controls)
            yield {
                "id":       counter.next_id(),
                "source":   "kubescape",
                "type":     "misconfig",
                "ruleId":   ctrl_id,
                "severity": _kubescape_severity(score),
                "target":   target,
                "title":    name,
            }


def _kubescape_target(resource_id: str) -> str:
    """Resolve Kubescape's ``[apiGroup/]apiVersion/Kind/[namespace/]name`` into
    the inventory's ``"<ns>/<name>"`` form. Cluster-scoped resources (no
    namespace component) collapse to ``"cluster"`` so the engine treats them
    the same as the PoC fixture's CIS row.

    Heuristic: K8s namespaces are DNS-1123 labels (lowercase). Kinds are
    CamelCase. If the segment immediately before the name starts with an
    uppercase letter it's a Kind, meaning the resource has no namespace.
    """
    if not resource_id:
        return "cluster"
    parts = [p for p in resource_id.split("/") if p]
    if len(parts) < 2:
        return "cluster"
    name, parent = parts[-1], parts[-2]
    if parent[:1].isupper():
        return "cluster"
    return f"{parent}/{name}"


def _kubescape_score(ctrl: dict, summary_controls: dict) -> float:
    score = ctrl.get("scoreFactor") or ctrl.get("baseScore")
    if score is None:
        ctrl_id = ctrl.get("controlID")
        summary = summary_controls.get(ctrl_id) if isinstance(summary_controls, dict) else None
        if isinstance(summary, dict):
            score = summary.get("scoreFactor") or summary.get("baseScore")
    try:
        return float(score) if score is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _kubescape_severity(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "medium"  # default when score is missing — better than dropping the finding


# ---------------------------------------------------------------------------
# Orchestrator — run all available scanners against an Inventory
# ---------------------------------------------------------------------------

@dataclass
class ScanRun:
    """Combined output of a multi-scanner run."""
    findings: list = field(default_factory=list)
    scanners: list = field(default_factory=list)   # list[ScannerResult]

    def metadata(self) -> dict:
        """Shape for inclusion in the report."""
        return {
            "scanners": [
                {
                    "name":           s.name,
                    "status":         s.status,
                    "findings_count": s.findings_count,
                    "reason":         s.reason,
                    **({"duration_ms": s.duration_ms} if s.duration_ms is not None else {}),
                }
                for s in self.scanners
            ],
        }


def run_all(
    inventory: dict,
    *,
    runner: Optional[Runner] = None,
    images_only: bool = False,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
) -> ScanRun:
    """Run every available scanner against the given inventory. Missing
    scanners degrade to ``skipped`` results — the run continues."""
    images = unique_images(inventory.get("workloads") or [])

    findings: list = []
    scanners: list = []

    trivy_findings, trivy_result = run_trivy(images, runner=runner)
    findings += trivy_findings
    scanners.append(trivy_result)

    if not images_only:
        kb_findings, kb_result = run_kube_bench(runner=runner)
        findings += kb_findings
        scanners.append(kb_result)

        ks_findings, ks_result = run_kubescape(
            runner=runner, kubeconfig=kubeconfig, context=context,
        )
        findings += ks_findings
        scanners.append(ks_result)

    return ScanRun(findings=findings, scanners=scanners)
