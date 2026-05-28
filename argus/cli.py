"""argus/cli.py — ``argus scan`` entry point (v3 engine).

Wires Phase-1 (inventory) + Phase-2 (scanners) + accepted-risk governance into
the v3 attack-graph engine:

    python3 -m argus.cli scan \\
        --kubeconfig ~/.kube/config --context my-cluster \\
        --accepted-risks ./accepted-risks --out ./out

Pipeline (every step read-only)::

    collect_inventory()
        → scanners.run_all(inventory)
        → accepted_risks.load + apply (filters accepted findings out)
        → threat_intel.refresh(cves_for_epss=...)            # LIVE CISA KEV + EPSS
        → engine.analyse(inventory, active_findings, intel)
        → engine.render_md(report) + report.json
        → print summary

Exit codes:
  0  — scan completed (findings ≠ failure)
  1  — unexpected error
  2  — cluster unreachable (config / auth / network)

The v3 engine's correlation, choke-point analysis, and threat-intel handling
are NEVER mutated from here. The CLI only:

  * filters accepted findings BEFORE the engine sees them;
  * appends a small "Accepted risks" + "Scanners" tail to the markdown;
  * mixes the scan metadata into the JSON next to the engine output.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Optional

# Local imports — make sure both ``argus.*`` and ``argus.engine_v3.*`` work
# whether we're invoked via ``python -m argus.cli`` or
# ``python argus/cli.py``.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from argus import accepted_risks, inventory, scanners            # noqa: E402
from argus.engine_v3 import engine, threat_intel                 # noqa: E402


# ---------------------------------------------------------------------------
# Exceptions we map to specific exit codes
# ---------------------------------------------------------------------------

class ClusterUnreachable(Exception):
    """Raised when we can't talk to the cluster API (config/auth/network).
    Surfaces as exit code 2 — distinct from a successful scan that found
    things."""


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="ARGUS — read-only Kubernetes attack-graph scanner (v3).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a cluster and write a posture report")
    scan.add_argument("--kubeconfig", help="path to kubeconfig file (default: KUBECONFIG env or ~/.kube/config)")
    scan.add_argument("--context", help="kube context to use")
    scan.add_argument("--in-cluster", action="store_true",
                      help="use the in-cluster ServiceAccount token instead of a kubeconfig")
    scan.add_argument("--cluster-name", default=None,
                      help="cluster name to record in the report (default: --context, then 'cluster')")
    scan.add_argument("--accepted-risks", metavar="DIR", default=None,
                      help="directory of accepted-risk .md files (optional)")
    scan.add_argument("--out", metavar="DIR", default="./out",
                      help="output directory (default: ./out)")
    scan.add_argument("--images-only", action="store_true",
                      help="run only Trivy on workload images; skip kube-bench and Kubescape")
    scan.add_argument("--no-network", action="store_true",
                      help="skip the live CISA KEV / EPSS fetch (use cache + override only)")
    scan.add_argument("--quiet", action="store_true", help="suppress info logging")

    return p


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    _configure_logging(quiet=args.quiet)
    log = logging.getLogger("argus")

    cluster_name = args.cluster_name or args.context or "cluster"

    try:
        inv = _collect_inventory(
            cluster_name=cluster_name,
            kubeconfig=args.kubeconfig,
            context=args.context,
            in_cluster=args.in_cluster,
        )
    except ClusterUnreachable as e:
        log.error("Cluster unreachable: %s", e)
        return 2

    log.info("Collected inventory: %d workloads, %d service-accounts, "
             "%d secrets, %d nodes, %d netpols",
             len(inv["workloads"]), len(inv["serviceAccounts"]),
             len(inv["secrets"]), len(inv["nodes"]), len(inv["networkPolicies"]))

    # ---- scanners -----------------------------------------------------------
    scan_run = scanners.run_all(
        inv,
        images_only=args.images_only,
        kubeconfig=args.kubeconfig,
        context=args.context,
    )
    for s in scan_run.scanners:
        log.info("  scanner %-10s %-8s findings=%d  %s",
                 s.name, s.status, s.findings_count, s.reason)

    # ---- accepted-risk governance ------------------------------------------
    ars = []
    ar_result = accepted_risks.ApplyResult(active_findings=scan_run.findings)
    if args.accepted_risks:
        if os.path.isdir(args.accepted_risks):
            ars = accepted_risks.load(args.accepted_risks)
            ar_result = accepted_risks.apply(scan_run.findings, ars, inv)
            log.info("Accepted-risk policy: %d active, %d accepted, %d refused, "
                     "%d auto-reopened",
                     len(ars), len(ar_result.accepted),
                     len(ar_result.refusals), len(ar_result.auto_reopened))
        else:
            log.warning("--accepted-risks %s is not a directory; continuing without policies",
                        args.accepted_risks)

    # ---- threat intel -------------------------------------------------------
    cves = [f["cve"] for f in ar_result.active_findings if f.get("cve")]
    intel = threat_intel.refresh(cves_for_epss=cves, allow_network=not args.no_network)
    intel_stats = intel.stats()
    log.info("Threat intel: source=%s KEV=%d EPSS=%d (catalog %s)",
             intel_stats["source"], intel_stats["kev_count"],
             intel_stats["epss_count"], intel_stats["version"])

    # ---- engine -------------------------------------------------------------
    report = engine.analyse(inv, ar_result.active_findings, intel)

    md = engine.render_md(report) + _ar_section(ar_result) + _scanner_section(scan_run)
    json_blob = _build_json_report(report, inv, ar_result, scan_run)

    os.makedirs(args.out, exist_ok=True)
    md_path = os.path.join(args.out, "report.md")
    json_path = os.path.join(args.out, "report.json")
    with open(md_path, "w") as f:
        f.write(md)
    with open(json_path, "w") as f:
        json.dump(json_blob, f, indent=2, default=str)

    _print_summary(report, ar_result, scan_run, md_path)
    return 0


# ---------------------------------------------------------------------------
# Cluster connection — wrapped so tests can mock and so config errors map to
# a clean exit code 2.
# ---------------------------------------------------------------------------

def _collect_inventory(*, cluster_name: str, kubeconfig: Optional[str],
                      context: Optional[str], in_cluster: bool) -> dict:
    try:
        return inventory.collect_inventory(
            cluster_name, kubeconfig=kubeconfig, context=context, in_cluster=in_cluster,
        )
    except ImportError as e:
        raise SystemExit(
            "argus: the 'kubernetes' Python package is required for live "
            "scans. Install it via `pip install -r requirements.txt`. "
            f"(import error: {e})"
        )
    except Exception as e:                                    # noqa: BLE001
        # ApiException, ConfigException, ConnectionError → "cluster unreachable".
        raise ClusterUnreachable(str(e) or e.__class__.__name__) from e


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def _build_json_report(report: dict, inv: dict,
                       ar_result: accepted_risks.ApplyResult,
                       scan_run: scanners.ScanRun) -> dict:
    """v3 engine output + additive blocks for scan metadata, accepted-risk
    governance, and downstream-mapper context.

    Engine output keys are never renamed or transformed. The extra
    ``workloads`` and ``activeFindings`` blocks are there so an external
    consumer (e.g. the TS tunnel-client mapping v3 → wire PostureSnapshot)
    has every piece of context it needs from a single file:

      * ``workloads``      — slim view of the inventory (id/kind/ns/image)
                             for mapping ``target`` ids → ResourceRef.
      * ``activeFindings`` — the raw scanner findings post-AR filter, with
                             ``source``/``severity``/``cve`` preserved. The
                             v3 engine's ``findings[]`` drops these when it
                             scores; consumers join on ``id`` to recover them.
    """
    return {
        **report,
        "scannedAt":     inv["scannedAt"],
        "acceptedRisks": ar_result.accepted,
        "refusals":      ar_result.refusals,
        "autoReopened":  ar_result.auto_reopened,
        "workloads": [
            {"id": w["id"], "kind": w.get("kind", "Workload"),
             "namespace": w["namespace"], "image": w.get("image", "")}
            for w in inv.get("workloads") or []
        ],
        "activeFindings": list(ar_result.active_findings),
        "metadata": {
            "scanners":     scan_run.metadata()["scanners"],
            "threat_intel": report.get("intel"),
        },
    }


def _ar_section(ar_result: accepted_risks.ApplyResult) -> str:
    if not (ar_result.accepted or ar_result.refusals or ar_result.auto_reopened):
        return ""
    out = ["\n## Accepted risks (mitigated — suppressed from active feed)\n"]
    for a in ar_result.accepted:
        ctrls = ", ".join(f"{c['type']}:{c['status']}" for c in a["controls"])
        out.append(f"- **{a['finding']}** {a.get('title', '')} — accepted under "
                   f"`{a['ar']}` by {a['owner']}, expires {a['expires']}. Controls: {ctrls}")
    if ar_result.refusals:
        out.append("\n### Refusals (over-broad selectors blocked)")
        for r in ar_result.refusals:
            out.append(f"- `{r['ar']}` → {r['finding']}: {r['reason']}")
    if ar_result.auto_reopened:
        out.append("\n### Auto-reopened (compensating control failed)")
        for r in ar_result.auto_reopened:
            out.append(f"- `{r['ar']}` → {r['finding']}: {r['reason']}")
    out.append("")
    return "\n".join(out)


def _scanner_section(scan_run: scanners.ScanRun) -> str:
    lines = ["\n## Scanners\n", "| Scanner | Status | Findings | Note |", "|---|---|---|---|"]
    for s in scan_run.scanners:
        note = (s.reason or "").replace("|", "\\|")
        lines.append(f"| {s.name} | {s.status} | {s.findings_count} | {note} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Summary — v3-shaped headline numbers.
# ---------------------------------------------------------------------------

def _print_summary(report: dict, ar_result: accepted_risks.ApplyResult,
                   scan_run: scanners.ScanRun, md_path: str) -> None:
    intel = report.get("intel") or {}
    chokes = report.get("chokePoints") or []
    print()
    print(f"[argus] -> wrote {md_path}")
    print()
    print("[argus] Summary:")
    print(f"        Cluster {report['cluster']} scored {report['riskScore']}/100.")
    print(f"        Threat intel: source={intel.get('source')} KEV={intel.get('kev_count')} "
          f"(catalog {intel.get('version')}).")
    print(f"        {len(report.get('reachableJewels') or [])} crown-jewel target(s) reachable "
          f"from the internet today.")
    if chokes:
        print("        Top fixes (choke-point analysis):")
        for ch in chokes[:4]:
            print(f"          breaks {ch['breaks']}: {engine.describe(ch['control'])}")
    if ar_result.accepted or ar_result.refusals or ar_result.auto_reopened:
        print(f"        Accepted: {len(ar_result.accepted)}; refused: "
              f"{len(ar_result.refusals)}; auto-reopened: {len(ar_result.auto_reopened)}.")
    skipped = [s.name for s in scan_run.scanners if s.status != "ran"]
    if skipped:
        print(f"        Scanners not run: {', '.join(skipped)}.")
    print("        Nothing was modified. All actions were read-only.")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _configure_logging(*, quiet: bool) -> None:
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr, force=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
