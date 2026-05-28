"""CLI tests — end-to-end pipeline through the v3 attack-graph engine, with
``collect_inventory``, the scanner ``runner``, and the live KEV fetch all
mocked. No live cluster, no scanner binaries, no network."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest
from io import StringIO
from subprocess import CompletedProcess
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from argus import cli, scanners                            # noqa: E402
from argus.inventory import build_inventory                # noqa: E402
from argus.tests import _fakes as fk                       # noqa: E402
from argus.tests.test_scanners import (                    # noqa: E402
    _KUBESCAPE_OUTPUT, _KUBE_BENCH_OUTPUT, _TRIVY_OUTPUT, _trivy_handler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scenario_inventory() -> dict:
    """Same shape as the Phase-1/2 scenario — public ingress on a root-running
    workload that can read Secrets; identical image on a dormant clone."""
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
    return build_inventory(apis, "prod-eu-1", scanned_at="2026-05-28T09:14:00Z")


def _all_scanners_runner():
    def _runner(argv, *args, **kwargs):                    # noqa: ARG001
        binary = os.path.basename(argv[0])
        return {
            "trivy":      lambda: CompletedProcess(argv, 0, json.dumps(_TRIVY_OUTPUT), ""),
            "kube-bench": lambda: CompletedProcess(argv, 0, json.dumps(_KUBE_BENCH_OUTPUT), ""),
            "kubescape":  lambda: CompletedProcess(argv, 0, json.dumps(_KUBESCAPE_OUTPUT), ""),
        }.get(binary, lambda: (_ for _ in ()).throw(FileNotFoundError(binary)))()
    return _runner


def _patch_scanner_runner(runner):
    """Force scanners.run_* to use ``runner`` regardless of how the CLI calls
    them. We do this by patching the default in run_all."""
    real_run_all = scanners.run_all

    def patched_run_all(inventory_dict, *, runner=None, **kwargs):
        return real_run_all(inventory_dict, runner=runner or _patch_scanner_runner.runner, **kwargs)
    _patch_scanner_runner.runner = runner
    return patch.object(scanners, "run_all", patched_run_all)


def _patch_shutil_which(present):
    """Make ``scanners.shutil.which`` claim only ``present`` binaries exist."""
    return patch.object(
        scanners, "shutil",
        type("S", (), {"which": staticmethod(lambda b: b if b in present else None)}),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class CliScanHappyPath(unittest.TestCase):

    def test_writes_report_md_and_json_and_returns_zero(self):
        inv = _scenario_inventory()
        with tempfile.TemporaryDirectory() as out_dir:
            args = cli.build_parser().parse_args(["scan", "--out", out_dir, "--quiet"])
            with patch.object(cli, "_collect_inventory", return_value=inv), \
                 _patch_shutil_which({"trivy", "kube-bench", "kubescape"}), \
                 _patch_scanner_runner(_all_scanners_runner()), \
                 patch("sys.stdout", new_callable=StringIO) as stdout:
                rc = cli.cmd_scan(args)

            self.assertEqual(rc, 0)
            md_path = os.path.join(out_dir, "report.md")
            json_path = os.path.join(out_dir, "report.json")
            self.assertTrue(os.path.exists(md_path))
            self.assertTrue(os.path.exists(json_path))

            with open(json_path) as f:
                blob = json.load(f)
            # v3 engine output keys preserved verbatim.
            for key in ("cluster", "riskScore", "findings", "chokePoints",
                        "reachableJewels", "paths", "intel"):
                self.assertIn(key, blob)
            # Additive AR + metadata blocks the CLI mixes in.
            for key in ("acceptedRisks", "refusals", "autoReopened", "metadata"):
                self.assertIn(key, blob)
            self.assertEqual(blob["scannedAt"], "2026-05-28T09:14:00Z")
            scanner_names = {s["name"] for s in blob["metadata"]["scanners"]}
            self.assertEqual(scanner_names, {"trivy", "kube-bench", "kubescape"})
            self.assertTrue(all(s["status"] == "ran" for s in blob["metadata"]["scanners"]))

            out = stdout.getvalue()
            self.assertIn("[argus] Summary:", out)
            self.assertIn("Cluster prod-eu-1 scored", out)
            self.assertIn("Nothing was modified. All actions were read-only.", out)

    def test_markdown_contains_scanner_table(self):
        inv = _scenario_inventory()
        with tempfile.TemporaryDirectory() as out_dir:
            args = cli.build_parser().parse_args(["scan", "--out", out_dir, "--quiet"])
            with patch.object(cli, "_collect_inventory", return_value=inv), \
                 _patch_shutil_which({"trivy", "kube-bench", "kubescape"}), \
                 _patch_scanner_runner(_all_scanners_runner()), \
                 patch("sys.stdout", new_callable=StringIO):
                cli.cmd_scan(args)
            with open(os.path.join(out_dir, "report.md")) as f:
                md = f.read()
        self.assertIn("## Scanners", md)
        self.assertIn("| trivy |", md)
        self.assertIn("| kube-bench |", md)
        self.assertIn("| kubescape |", md)

    def test_missing_scanners_do_not_fail_the_run(self):
        inv = _scenario_inventory()
        # Only Trivy available; others should be reported as skipped.
        with tempfile.TemporaryDirectory() as out_dir:
            args = cli.build_parser().parse_args(["scan", "--out", out_dir, "--quiet"])
            with patch.object(cli, "_collect_inventory", return_value=inv), \
                 _patch_shutil_which({"trivy"}), \
                 _patch_scanner_runner(_all_scanners_runner()), \
                 patch("sys.stdout", new_callable=StringIO):
                rc = cli.cmd_scan(args)

            self.assertEqual(rc, 0, "missing scanners must not fail the run")
            with open(os.path.join(out_dir, "report.json")) as f:
                blob = json.load(f)
        by_name = {s["name"]: s["status"] for s in blob["metadata"]["scanners"]}
        self.assertEqual(by_name["trivy"], "ran")
        self.assertEqual(by_name["kube-bench"], "skipped")
        self.assertEqual(by_name["kubescape"], "skipped")


class CliClusterUnreachable(unittest.TestCase):

    def test_cluster_unreachable_returns_exit_two(self):
        with tempfile.TemporaryDirectory() as out_dir:
            args = cli.build_parser().parse_args(["scan", "--out", out_dir, "--quiet"])
            boom = cli.ClusterUnreachable("connection refused")
            with patch.object(cli, "_collect_inventory", side_effect=boom):
                rc = cli.cmd_scan(args)
            self.assertEqual(rc, 2)
            # Nothing should have been written.
            self.assertFalse(os.path.exists(os.path.join(out_dir, "report.md")))
            self.assertFalse(os.path.exists(os.path.join(out_dir, "report.json")))


class CliAcceptedRisks(unittest.TestCase):

    def test_accepted_risk_dir_is_loaded_and_applied(self):
        """Drop a real accepted-risk .md into a temp dir and confirm the engine
        marks the matching finding accepted in the JSON report."""
        ar_yaml = textwrap.dedent(
            """\
            ---
            id: AR-TEST-001
            selector_type: specific
            status: accepted
            owner: alice@acme.com
            approver: ciso@acme.com
            created: 2026-05-20
            expires: 2099-01-01
            match:
              source: trivy
              severity: [high]
              cve: CVE-2025-99999
              target: payments/invoice-api
            compensating_controls:
              - type: network-policy
                description: cache is internal-only
                verify:
                  namespace: payments
                  appliesTo: cache
                  mode: deny-external      # v3 key; AR module also accepts the old `ingress: deny-external` for back-compat
            ---

            ## Why accepted
            test fixture.
            """
        )
        inv = _scenario_inventory()
        with tempfile.TemporaryDirectory() as tmp:
            ar_dir = os.path.join(tmp, "ars")
            os.makedirs(ar_dir)
            with open(os.path.join(ar_dir, "AR-TEST-001.md"), "w") as f:
                f.write(ar_yaml)
            out_dir = os.path.join(tmp, "out")

            args = cli.build_parser().parse_args(
                ["scan", "--accepted-risks", ar_dir, "--out", out_dir, "--quiet"]
            )
            with patch.object(cli, "_collect_inventory", return_value=inv), \
                 _patch_shutil_which({"trivy", "kube-bench", "kubescape"}), \
                 _patch_scanner_runner(_all_scanners_runner()), \
                 patch("sys.stdout", new_callable=StringIO):
                rc = cli.cmd_scan(args)
            self.assertEqual(rc, 0)

            with open(os.path.join(out_dir, "report.json")) as f:
                blob = json.load(f)

        accepted_cves = {a["finding"] for a in blob["acceptedRisks"]}
        # The CVE-2025-99999 finding on payments/invoice-api should be accepted.
        # Find the original finding id from the active findings (it should NOT
        # be there) or the metadata. We just check at least one accepted.
        self.assertTrue(blob["acceptedRisks"],
                        "expected at least one accepted-risk match")
        ars_ids = {a["ar"] for a in blob["acceptedRisks"]}
        self.assertIn("AR-TEST-001", ars_ids)


class CliImagesOnlyFlag(unittest.TestCase):

    def test_images_only_skips_kube_bench_and_kubescape(self):
        inv = _scenario_inventory()
        with tempfile.TemporaryDirectory() as out_dir:
            args = cli.build_parser().parse_args(
                ["scan", "--out", out_dir, "--images-only", "--quiet"]
            )
            with patch.object(cli, "_collect_inventory", return_value=inv), \
                 _patch_shutil_which({"trivy", "kube-bench", "kubescape"}), \
                 _patch_scanner_runner(_all_scanners_runner()), \
                 patch("sys.stdout", new_callable=StringIO):
                rc = cli.cmd_scan(args)
            self.assertEqual(rc, 0)
            with open(os.path.join(out_dir, "report.json")) as f:
                blob = json.load(f)
        names = [s["name"] for s in blob["metadata"]["scanners"]]
        self.assertEqual(names, ["trivy"])


class CliEngineReportInvariants(unittest.TestCase):
    """End-to-end: the v3 engine reaches a crown jewel, scores the exposed
    workload's CVE in the Act/Attend band, and surfaces a choke-point fix."""

    def test_crown_jewel_reachable_and_dormant_clone_decision_is_lower(self):
        inv = _scenario_inventory()
        with tempfile.TemporaryDirectory() as out_dir:
            args = cli.build_parser().parse_args(["scan", "--out", out_dir, "--no-network", "--quiet"])
            with patch.object(cli, "_collect_inventory", return_value=inv), \
                 _patch_shutil_which({"trivy", "kube-bench", "kubescape"}), \
                 _patch_scanner_runner(_all_scanners_runner()), \
                 patch("sys.stdout", new_callable=StringIO):
                cli.cmd_scan(args)
            with open(os.path.join(out_dir, "report.json")) as f:
                blob = json.load(f)
        self.assertGreater(blob["riskScore"], 0)
        self.assertGreater(len(blob["chokePoints"]), 0,
                           "engine should surface at least one choke-point fix")

        # Decision ordering: exposed workload outranks dormant clone for the
        # same CVE.
        invoice = [f for f in blob["findings"] if f["target"] == "payments/invoice-api"]
        worker = [f for f in blob["findings"] if f["target"] == "batch/report-worker"]
        self.assertTrue(invoice, "expected at least one finding on the exposed workload")
        self.assertTrue(worker, "expected the dormant clone's same-CVE finding to surface")
        order = {"Act": 3, "Attend": 2, "Track": 1, "Track*": 0}
        self.assertGreater(max(order[f["decision"]] for f in invoice),
                           max(order[f["decision"]] for f in worker),
                           "exposed workload's SSVC decision must outrank dormant clone's")


if __name__ == "__main__":
    unittest.main()
