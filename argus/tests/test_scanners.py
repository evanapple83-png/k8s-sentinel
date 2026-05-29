"""Phase 2 scanner-adapter tests. Each adapter is invoked with a fake
``subprocess.run`` so we never need the real binaries; the fake returns
realistic JSON pulled from the actual schemas. Coverage:

* Trivy: per-image scan, severity mapping, CVSS pickup, per-workload duplication
  when one image is used by N workloads, missing binary → skipped.
* kube-bench: FAIL → cis finding on ``target="cluster"``; PASS/WARN ignored.
* Kubescape: resourceID → ``ns/name``; failed control → misconfig finding with
  severity derived from scoreFactor; cluster-scoped resources collapse to
  ``"cluster"``.
* Orchestrator: ``run_all`` merges findings, reports ``ScannerResult`` per
  scanner, never crashes when a scanner is missing.
* Engine round-trip: feed the scanner output + Phase-1 inventory into
  ``argus_engine.correlate`` and confirm it produces the same kind of attack
  path the PoC fixtures produce.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from subprocess import CompletedProcess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from argus import scanners                         # noqa: E402
from argus.inventory import build_inventory       # noqa: E402
from argus.tests import _fakes as fk              # noqa: E402


# ---------------------------------------------------------------------------
# Helpers — build a fake subprocess.run that dispatches per scanner binary
# ---------------------------------------------------------------------------

def make_runner(handlers):
    """Construct a ``subprocess.run``-shaped callable backed by ``handlers``,
    a dict ``{binary_name: callable(argv) -> (returncode, stdout, stderr)}``."""
    def _runner(argv, *args, **kwargs):           # noqa: ARG001 — matches subprocess.run
        bin_name = os.path.basename(argv[0])
        if bin_name not in handlers:
            raise FileNotFoundError(argv[0])
        rc, out, err = handlers[bin_name](argv)
        return CompletedProcess(args=argv, returncode=rc, stdout=out, stderr=err)
    return _runner


def with_which(monkeypatch_targets):
    """Patch ``shutil.which`` so adapters believe the requested binaries exist.
    Returns a context-managerish object via ``unittest.mock.patch``."""
    from unittest.mock import patch
    return patch.object(scanners, "shutil",
                        type("S", (), {"which": staticmethod(lambda b: b if b in monkeypatch_targets else None)}))


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

_TRIVY_OUTPUT = {
    "ArtifactName": "ghcr.io/acme/invoice-api:1.2.3",
    "Results": [
        {
            "Target": "ghcr.io/acme/invoice-api:1.2.3 (debian 12.1)",
            "Class": "os-pkgs",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-31337",
                    "PkgName": "libfoo",
                    "Severity": "CRITICAL",
                    "CVSS": {"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 9.5}},
                    "Title": "Remote code execution in libfoo < 2.1",
                },
                {
                    "VulnerabilityID": "CVE-2025-99999",
                    "PkgName": "libbar",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "Title": "Heap overflow in libbar",
                },
            ],
        }
    ],
}


def _trivy_handler(argv):
    # Last positional arg is the image. Respond with the same JSON regardless.
    return 0, json.dumps(_TRIVY_OUTPUT), ""


def _kubescape_file_handler(argv):
    """Mirror real kubescape (F14): write JSON to the --output file, print a
    human banner to stdout."""
    out = argv[argv.index("--output") + 1]
    with open(out, "w") as fh:
        json.dump(_KUBESCAPE_OUTPUT, fh)
    return 0, "Framework scanned: NSA\n──────────────\n", ""


class TrivyAdapterTests(unittest.TestCase):

    def test_two_workloads_share_image_yield_one_finding_each(self):
        images = {"ghcr.io/acme/invoice-api:1.2.3": ["payments/invoice-api", "batch/report-worker"]}
        runner = make_runner({"trivy": _trivy_handler})
        with with_which({"trivy"}):
            findings, result = scanners.run_trivy(images, runner=runner)
        self.assertEqual(result.status, "ran")
        # 2 vulns × 2 workloads = 4 findings.
        self.assertEqual(len(findings), 4)
        cves_by_target = {}
        for f in findings:
            cves_by_target.setdefault(f["target"], []).append(f["cve"])
        self.assertEqual(set(cves_by_target), {"payments/invoice-api", "batch/report-worker"})
        self.assertEqual(
            sorted(cves_by_target["payments/invoice-api"]),
            ["CVE-2025-99999", "CVE-2026-31337"],
        )

    def test_severity_and_cvss_normalised(self):
        images = {"ghcr.io/acme/invoice-api:1.2.3": ["payments/invoice-api"]}
        runner = make_runner({"trivy": _trivy_handler})
        with with_which({"trivy"}):
            findings, _ = scanners.run_trivy(images, runner=runner)
        crit = next(f for f in findings if f["cve"] == "CVE-2026-31337")
        self.assertEqual(crit["severity"], "critical")
        self.assertEqual(crit["cvss"], 9.8)        # picks max across vendors
        self.assertEqual(crit["type"], "cve")
        self.assertEqual(crit["source"], "trivy")
        self.assertTrue(crit["id"].startswith("trivy-"))

    def test_missing_binary_returns_skipped_no_findings(self):
        images = {"ghcr.io/acme/invoice-api:1.2.3": ["payments/invoice-api"]}
        runner = make_runner({})  # binary not in handlers
        with with_which(set()):   # shutil.which returns None
            findings, result = scanners.run_trivy(images, runner=runner)
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "skipped")
        self.assertIn("not found", result.reason)

    def test_empty_image_set_skipped_with_reason(self):
        findings, result = scanners.run_trivy({}, runner=make_runner({}))
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.findings_count, 0)


# ---------------------------------------------------------------------------
# kube-bench
# ---------------------------------------------------------------------------

_KUBE_BENCH_OUTPUT = {
    "Controls": [
        {
            "id": "1",
            "version": "cis-1.7",
            "tests": [
                {
                    "section": "1.2",
                    "results": [
                        {"test_number": "1.2.16", "test_desc": "Ensure --anonymous-auth=false on kubelet",
                         "status": "FAIL"},
                        {"test_number": "1.2.17", "test_desc": "Ensure --profiling=false",
                         "status": "WARN"},
                        {"test_number": "1.2.18", "test_desc": "Some passing thing",
                         "status": "PASS"},
                    ],
                }
            ],
        }
    ],
}


class KubeBenchAdapterTests(unittest.TestCase):

    def test_only_fails_become_findings_targeted_at_cluster(self):
        runner = make_runner({"kube-bench": lambda argv: (0, json.dumps(_KUBE_BENCH_OUTPUT), "")})
        with with_which({"kube-bench"}):
            findings, result = scanners.run_kube_bench(runner=runner)
        self.assertEqual(result.status, "ran")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "kube-bench")
        self.assertEqual(f["type"], "cis")
        self.assertEqual(f["target"], "cluster")
        self.assertEqual(f["ruleId"], "1.2.16")
        self.assertEqual(f["severity"], "medium")

    def test_binary_missing_is_skipped(self):
        with with_which(set()):
            findings, result = scanners.run_kube_bench(runner=make_runner({}))
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "skipped")


# ---------------------------------------------------------------------------
# Kubescape
# ---------------------------------------------------------------------------

_KUBESCAPE_OUTPUT = {
    "summaryDetails": {
        "controls": {
            "C-0017": {"name": "Containers running as root", "scoreFactor": 7.0},
            "C-0015": {"name": "Read sensitive data — Secrets", "scoreFactor": 8.0},
        }
    },
    "results": [
        {
            "resourceID": "apps/v1/Deployment/payments/invoice-api",
            "controls": {
                "C-0017": {"controlID": "C-0017", "name": "Containers running as root",
                           "scoreFactor": 7.0,
                           "status": {"status": "failed"}},
                "C-0015": {"controlID": "C-0015", "name": "Read sensitive data — Secrets",
                           "scoreFactor": 8.0,
                           "status": {"status": "failed"}},
                "C-0001": {"controlID": "C-0001", "name": "Some passing control",
                           "status": {"status": "passed"}},
            },
        },
        {
            "resourceID": "rbac.authorization.k8s.io/v1/ClusterRole/cluster-admin",
            "controls": {
                "C-0035": {"controlID": "C-0035", "name": "Cluster-admin binding",
                           "scoreFactor": 9.5,
                           "status": {"status": "failed"}},
            },
        },
    ],
}


class KubescapeAdapterTests(unittest.TestCase):

    def setUp(self):
        self.runner = make_runner({"kubescape": _kubescape_file_handler})

    def test_failed_control_becomes_finding_on_ns_name_target(self):
        with with_which({"kubescape"}):
            findings, result = scanners.run_kubescape(runner=self.runner)
        self.assertEqual(result.status, "ran")
        invoice = [f for f in findings if f["target"] == "payments/invoice-api"]
        self.assertEqual({f["ruleId"] for f in invoice}, {"C-0017", "C-0015"})
        for f in invoice:
            self.assertEqual(f["type"], "misconfig")
            self.assertEqual(f["source"], "kubescape")

    def test_cluster_scoped_resource_collapses_to_cluster_target(self):
        with with_which({"kubescape"}):
            findings, _ = scanners.run_kubescape(runner=self.runner)
        cluster_finding = next(f for f in findings if f["ruleId"] == "C-0035")
        self.assertEqual(cluster_finding["target"], "cluster")
        self.assertEqual(cluster_finding["severity"], "critical")  # score 9.5

    def test_severity_derived_from_score_factor(self):
        with with_which({"kubescape"}):
            findings, _ = scanners.run_kubescape(runner=self.runner)
        sev_by_rule = {f["ruleId"]: f["severity"] for f in findings}
        self.assertEqual(sev_by_rule["C-0017"], "high")   # 7.0
        self.assertEqual(sev_by_rule["C-0015"], "high")   # 8.0
        self.assertEqual(sev_by_rule["C-0035"], "critical")  # 9.5

    def test_passed_controls_are_ignored(self):
        with with_which({"kubescape"}):
            findings, _ = scanners.run_kubescape(runner=self.runner)
        self.assertFalse(any(f["ruleId"] == "C-0001" for f in findings))

    def test_missing_binary_skipped(self):
        with with_which(set()):
            findings, result = scanners.run_kubescape(runner=make_runner({}))
        self.assertEqual(findings, [])
        self.assertEqual(result.status, "skipped")


# ---------------------------------------------------------------------------
# Orchestrator + engine round-trip
# ---------------------------------------------------------------------------

def _scenario_inventory():
    """Reuse the Phase-1 scenario so target mapping has a real Inventory to
    match against."""
    invoice = fk.deployment(
        name="invoice-api", namespace="payments", replicas=3, ready_replicas=3,
        image="ghcr.io/acme/invoice-api:1.2.3", pod_labels={"app": "invoice-api"},
        service_account_name="invoice-sa", run_as_non_root=False,
        volumes=[fk.secret_volume("db-credentials")],
    )
    worker = fk.deployment(
        name="report-worker", namespace="batch", replicas=0, ready_replicas=0,
        image="ghcr.io/acme/invoice-api:1.2.3", pod_labels={"app": "report-worker"},
    )
    cache = fk.deployment(
        name="cache", namespace="payments", replicas=2, ready_replicas=2,
        image="redis:7.2.0", pod_labels={"app": "cache"}, run_as_non_root=True,
    )
    invoice_svc = fk.service(name="invoice-svc", namespace="payments",
                             selector={"app": "invoice-api"}, type_="ClusterIP")
    invoice_ing = fk.ingress(name="invoice-ing", namespace="payments",
                             host="invoice.acme.com", backend_service="invoice-svc")
    cache_netpol = fk.network_policy(name="cache-deny", namespace="payments",
                                     match_labels={"app": "cache"},
                                     policy_types=("Ingress",), ingress=None)
    role_obj = fk.role(name="secret-reader", namespace="payments",
                       rules=[fk.rule(verbs=["get", "list"], resources=["secrets"])])
    binding = fk.role_binding(name="b", namespace="payments", role_name="secret-reader",
                              subjects=[fk.subject_sa("invoice-sa", "payments")])

    apis = fk.FakeApis(
        namespaces=["payments", "batch"],
        deployments=[invoice, worker, cache],
        services=[invoice_svc], ingresses=[invoice_ing], netpols=[cache_netpol],
        roles=[role_obj], role_bindings=[binding],
    )
    return build_inventory(apis, "prod-eu-1")


class RunAllOrchestratorTests(unittest.TestCase):

    def test_all_scanners_present_yields_merged_findings_and_metadata(self):
        runner = make_runner({
            "trivy":      _trivy_handler,
            "kube-bench": lambda argv: (0, json.dumps(_KUBE_BENCH_OUTPUT), ""),
            "kubescape":  _kubescape_file_handler,
        })
        with with_which({"trivy", "kube-bench", "kubescape"}):
            run = scanners.run_all(_scenario_inventory(), runner=runner)

        names = {s.name for s in run.scanners}
        self.assertEqual(names, {"trivy", "kube-bench", "kubescape"})
        self.assertTrue(all(s.status == "ran" for s in run.scanners))
        self.assertGreater(len(run.findings), 0)
        meta = run.metadata()
        self.assertEqual(len(meta["scanners"]), 3)
        # findings_count in metadata matches what each adapter actually emitted.
        per_source = {}
        for f in run.findings:
            per_source[f["source"]] = per_source.get(f["source"], 0) + 1
        for entry in meta["scanners"]:
            self.assertEqual(entry["findings_count"], per_source.get(entry["name"], 0))

    def test_missing_scanners_do_not_crash_and_are_reported_as_skipped(self):
        # Only Trivy available; the other two get FileNotFoundError → skipped.
        runner = make_runner({"trivy": _trivy_handler})
        with with_which({"trivy"}):
            run = scanners.run_all(_scenario_inventory(), runner=runner)
        statuses = {s.name: s.status for s in run.scanners}
        self.assertEqual(statuses["trivy"], "ran")
        self.assertEqual(statuses["kube-bench"], "skipped")
        self.assertEqual(statuses["kubescape"], "skipped")
        # We still got Trivy findings.
        self.assertTrue(any(f["source"] == "trivy" for f in run.findings))


class EngineRoundTripTests(unittest.TestCase):
    """End-to-end shape proof: feed inventory + scanner output into the v3
    engine and confirm it produces the headline behaviour — internet-exposed
    workload scores ``Act`` while the dormant clone is shoved into
    ``Track*`` (small exposure, no reachability)."""

    def test_engine_correlates_scanner_output_with_inventory(self):
        from argus.engine_v3 import engine, threat_intel
        inventory = _scenario_inventory()
        runner = make_runner({
            "trivy":      _trivy_handler,
            "kube-bench": lambda argv: (0, json.dumps(_KUBE_BENCH_OUTPUT), ""),
            "kubescape":  _kubescape_file_handler,
        })
        with with_which({"trivy", "kube-bench", "kubescape"}):
            run = scanners.run_all(inventory, runner=runner)

        # Override-only intel so this test never hits the network.
        intel = threat_intel.refresh(cves_for_epss=None, allow_network=False)
        report = engine.analyse(inventory, run.findings, intel)

        # The exposed workload's trivy CVE must outrank the dormant clone's
        # same-CVE finding (v3 reports SSVC decision + score; dormant clones
        # land in exposure=small with a low score).
        by_target = {}
        for f in report["findings"]:
            by_target.setdefault(f["target"], []).append(f)
        invoice = by_target.get("payments/invoice-api", [])
        worker = by_target.get("batch/report-worker", [])
        self.assertTrue(invoice, "expected at least one finding on the exposed workload")
        self.assertTrue(worker, "expected the dormant clone's same-CVE finding to surface")
        invoice_top = max((f["score"] for f in invoice), default=0)
        worker_top = max((f["score"] for f in worker), default=0)
        self.assertGreater(invoice_top, worker_top,
                           "exposed workload must outrank dormant clone")


if __name__ == "__main__":
    unittest.main()
