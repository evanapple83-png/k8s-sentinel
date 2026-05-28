"""Collector tests for the v3 schema. Each test pins one invariant that the
v3 engine relies on. No live cluster required — fake K8s API objects are
injected via ``argus.tests._fakes``."""
from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

from argus.inventory import build_inventory                                # noqa: E402
from argus.tests import _fakes as fk                                       # noqa: E402


# ---------------------------------------------------------------------------
# A representative fake cluster mirroring the v3 reference inventory shape.
# ---------------------------------------------------------------------------

def _scenario_apis() -> fk.FakeApis:
    # invoice-api: public, root, has secret ref + cloud identity, on node-1
    invoice = fk.deployment(
        name="invoice-api", namespace="payments", ready_replicas=3,
        image="acme/invoice-api:1.2.3", pod_labels={"app": "invoice-api"},
        service_account_name="invoice-sa",
        run_as_non_root=False, node_name="node-1",
        volumes=[fk.secret_volume("db-credentials")],
    )
    # dormant clone of the same image, on node-2
    report_worker = fk.deployment(
        name="report-worker", namespace="batch", ready_replicas=0,
        image="acme/invoice-api:1.2.3", pod_labels={"app": "report-worker"},
        node_name="node-2",
    )
    # internal cache, non-root
    cache = fk.deployment(
        name="cache", namespace="payments", ready_replicas=2,
        image="redis:7.2.0", pod_labels={"app": "cache"},
        run_as_non_root=True, node_name="node-2",
    )
    # legacy agent: privileged, hostPath, hostPID, SYS_ADMIN — exactly the
    # shape v3's container-escape edge looks for.
    legacy = fk.deployment(
        name="legacy-agent", namespace="platform", ready_replicas=1,
        image="acme/legacy-agent:0.9", pod_labels={"app": "legacy-agent"},
        privileged=True, host_pid=True, host_paths=["/"],
        added_capabilities=["SYS_ADMIN"], node_name="node-1",
    )

    svc_invoice = fk.service(name="invoice-svc", namespace="payments",
                             selector={"app": "invoice-api"}, type_="ClusterIP")
    ing_invoice = fk.ingress(name="invoice-ing", namespace="payments",
                             host="invoice.acme.com", backend_service="invoice-svc")
    np_cache = fk.network_policy(name="cache-deny", namespace="payments",
                                 match_labels={"app": "cache"},
                                 policy_types=("Ingress",), ingress=None)

    # SAs — invoice-sa carries an IRSA annotation; others are plain.
    sa_invoice = fk.service_account(
        name="invoice-sa", namespace="payments",
        cloud_identity="arn:aws:iam::1234:role/invoice-s3-rw",
    )
    sa_legacy = fk.service_account(name="legacy-sa", namespace="platform")
    sa_default_batch = fk.service_account(name="default", namespace="batch")
    sa_default_pay = fk.service_account(name="default", namespace="payments")

    role_obj = fk.role(name="secret-reader", namespace="payments",
                       rules=[fk.rule(verbs=["get", "list"], resources=["secrets"])])
    binding = fk.role_binding(name="invoice-binding", namespace="payments",
                              role_name="secret-reader",
                              subjects=[fk.subject_sa("invoice-sa", "payments")])

    return fk.FakeApis(
        namespaces=["payments", "batch", "platform"],
        deployments=[invoice, report_worker, cache, legacy],
        services=[svc_invoice], ingresses=[ing_invoice], netpols=[np_cache],
        nodes=["node-1", "node-2"],
        service_accounts=[sa_invoice, sa_legacy, sa_default_batch, sa_default_pay],
        roles=[role_obj], role_bindings=[binding],
    )


class InventoryTopLevelShape(unittest.TestCase):
    def test_top_level_keys_match_v3_contract(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1", scanned_at="2026-05-28T09:14:00Z")
        self.assertEqual(
            set(inv.keys()),
            {"cluster", "scannedAt", "workloads", "serviceAccounts",
             "cloudRoles", "secrets", "nodes", "networkPolicies"},
        )
        self.assertEqual(inv["cluster"], "prod-eu-1")
        self.assertEqual(inv["scannedAt"], "2026-05-28T09:14:00Z")
        self.assertEqual(inv["cloudRoles"], [], "cloudRoles must default to [] (cloud collector TODO)")
        self.assertEqual([n["id"] for n in inv["nodes"]], ["node-1", "node-2"])


class WorkloadDerivation(unittest.TestCase):

    def setUp(self):
        self.inv = build_inventory(_scenario_apis(), "prod-eu-1")
        self.by_id = {w["id"]: w for w in self.inv["workloads"]}

    def test_workload_fields_match_v3_engine(self):
        # Keys the v3 engine consumes — required.
        required = {"id", "namespace", "running", "image", "serviceAccount",
                    "node", "runAsRoot", "privileged", "hostPath", "hostPID",
                    "capabilities", "exposedVia"}
        # Keys the engine ignores but downstream consumers (TS wire mapping,
        # UI) rely on. The engine accepts extras silently.
        additive = {"kind"}
        for w in self.inv["workloads"]:
            self.assertTrue(required.issubset(w.keys()),
                            f"workload {w['id']} missing required keys "
                            f"{required - w.keys()}")
            self.assertTrue(w.keys() <= required | additive,
                            f"workload {w['id']} carries unexpected keys "
                            f"{w.keys() - (required | additive)}")
            self.assertIsInstance(w["hostPath"], list)
            self.assertIsInstance(w["capabilities"], list)
            self.assertIsInstance(w["hostPID"], bool)

    def test_workload_kind_is_recorded_for_downstream_consumers(self):
        self.assertEqual(self.by_id["payments/invoice-api"]["kind"], "Deployment")
        self.assertEqual(self.by_id["batch/report-worker"]["kind"], "Deployment")

    def test_running_flag_reflects_ready_replicas(self):
        self.assertTrue(self.by_id["payments/invoice-api"]["running"])
        self.assertFalse(self.by_id["batch/report-worker"]["running"])
        self.assertTrue(self.by_id["payments/cache"]["running"])

    def test_run_as_root_uses_explicit_overrides(self):
        self.assertTrue(self.by_id["payments/invoice-api"]["runAsRoot"])
        self.assertFalse(self.by_id["payments/cache"]["runAsRoot"])
        # report-worker has no securityContext anywhere → image default UID → root.
        self.assertTrue(self.by_id["batch/report-worker"]["runAsRoot"])

    def test_service_account_normalised_with_namespace(self):
        self.assertEqual(self.by_id["payments/invoice-api"]["serviceAccount"], "payments/invoice-sa")
        self.assertEqual(self.by_id["batch/report-worker"]["serviceAccount"], "batch/default")

    def test_node_recorded_when_pinned(self):
        self.assertEqual(self.by_id["payments/invoice-api"]["node"], "node-1")
        self.assertEqual(self.by_id["payments/cache"]["node"], "node-2")

    def test_legacy_agent_signals_container_escape_inputs(self):
        legacy = self.by_id["platform/legacy-agent"]
        self.assertTrue(legacy["privileged"])
        self.assertTrue(legacy["hostPID"])
        self.assertEqual(legacy["hostPath"], ["/"])
        self.assertIn("SYS_ADMIN", legacy["capabilities"])


class ExposureDerivation(unittest.TestCase):

    def test_ingress_with_host_attaches_to_selected_workload(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        invoice = next(w for w in inv["workloads"] if w["id"] == "payments/invoice-api")
        self.assertIn("ingress:invoice.acme.com", invoice["exposedVia"])

    def test_internal_workload_has_no_external_exposure(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        cache = next(w for w in inv["workloads"] if w["id"] == "payments/cache")
        self.assertEqual(cache["exposedVia"], [])

    def test_loadbalancer_service_marks_workload_publicly_exposed(self):
        apis = _scenario_apis()
        apis._services = [
            fk.service(name="invoice-lb", namespace="payments",
                       selector={"app": "invoice-api"}, type_="LoadBalancer"),
        ]
        apis._ingresses = []
        inv = build_inventory(apis, "prod-eu-1")
        invoice = next(w for w in inv["workloads"] if w["id"] == "payments/invoice-api")
        self.assertEqual(invoice["exposedVia"], ["loadbalancer:invoice-lb"])


class ServiceAccountGrouping(unittest.TestCase):

    def setUp(self):
        self.inv = build_inventory(_scenario_apis(), "prod-eu-1")
        self.by_id = {s["id"]: s for s in self.inv["serviceAccounts"]}

    def test_every_sa_listed_even_without_bindings(self):
        # Five SAs: invoice-sa, legacy-sa, batch/default, payments/default,
        # plus the synthesised entry for invoice-binding's subject.
        self.assertIn("payments/invoice-sa", self.by_id)
        self.assertIn("platform/legacy-sa", self.by_id)
        self.assertIn("batch/default", self.by_id)
        self.assertIn("payments/default", self.by_id)

    def test_rules_grouped_per_sa_with_verbs_resources_scope(self):
        invoice = self.by_id["payments/invoice-sa"]
        self.assertTrue(invoice["rules"])
        rule = invoice["rules"][0]
        self.assertEqual(set(rule.keys()), {"verbs", "resources", "scope"})
        self.assertEqual(rule["scope"], "payments")
        self.assertIn("secrets", rule["resources"])
        self.assertTrue(set(rule["verbs"]) & {"get", "list"})

    def test_cloud_identity_harvested_from_annotation(self):
        invoice = self.by_id["payments/invoice-sa"]
        self.assertEqual(invoice["cloudIdentity"],
                         "arn:aws:iam::1234:role/invoice-s3-rw")

    def test_sa_without_cloud_annotation_has_none(self):
        self.assertIsNone(self.by_id["platform/legacy-sa"]["cloudIdentity"])

    def test_clusterrolebinding_yields_cluster_scope(self):
        apis = _scenario_apis()
        apis._cluster_roles = [
            fk.cluster_role(name="god",
                            rules=[fk.rule(verbs=["*"], resources=["*"])]),
        ]
        apis._cluster_role_bindings = [fk.cluster_role_binding(
            name="god-binding", role_name="god",
            subjects=[fk.subject_sa("default", "kube-system")],
        )]
        inv = build_inventory(apis, "prod-eu-1")
        god = next(s for s in inv["serviceAccounts"] if s["id"] == "kube-system/default")
        self.assertEqual(god["rules"][0]["scope"], "*")
        # Wildcard preserved verbatim — v3 engine expands it on its side.
        self.assertEqual(god["rules"][0]["resources"], ["*"])


class SecretCollection(unittest.TestCase):

    def test_secret_collected_from_volume_reference(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        ids = {s["id"] for s in inv["secrets"]}
        self.assertIn("payments/db-credentials", ids)

    def test_secret_has_v3_keys_only(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        for s in inv["secrets"]:
            self.assertEqual(set(s.keys()), {"id", "namespace", "sensitivity"})

    def test_secret_sensitivity_high_for_credential_name(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        db = next(s for s in inv["secrets"] if s["id"] == "payments/db-credentials")
        self.assertEqual(db["sensitivity"], "high")

    def test_secret_data_never_present_anywhere_in_output(self):
        """Hard guarantee: serialised inventory must not contain a Secret .data
        payload, full stop. Engine never needs it; auditors must be able to
        confirm by grep."""
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        blob = json.dumps(inv)
        self.assertNotIn('"data"', blob)
        for sec in inv["secrets"]:
            self.assertNotIn("data", sec.keys())

    def test_collector_does_not_call_list_secret(self):
        """Default RBAC forbids ``list`` on Secrets. Our fake CoreV1
        deliberately omits ``list_secret_*`` — if the collector ever calls
        it the test AttributeErrors and we know immediately."""
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        self.assertIsInstance(inv["secrets"], list)


class NetworkPolicyShape(unittest.TestCase):

    def test_empty_ingress_with_ingress_type_classified_deny_all(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        cache_np = [n for n in inv["networkPolicies"] if n["appliesTo"] == "cache"]
        self.assertEqual(len(cache_np), 1)
        self.assertEqual(cache_np[0]["namespace"], "payments")
        self.assertEqual(cache_np[0]["mode"], "deny-all")

    def test_external_cidr_rule_marks_policy_open(self):
        apis = _scenario_apis()
        apis._netpols = [fk.network_policy(
            name="open", namespace="payments", match_labels={"app": "cache"},
            policy_types=("Ingress",), allow_external_cidr="0.0.0.0/0",
        )]
        inv = build_inventory(apis, "prod-eu-1")
        self.assertEqual(inv["networkPolicies"][0]["mode"], "open")


class CloudRolesIsEmptyByDesign(unittest.TestCase):
    """cloudRoles requires a cloud-provider collector that hasn't been built
    yet. The v3 engine treats an empty list as 'no cloud-IAM reachability
    known' — this test pins that behaviour."""

    def test_cloudroles_is_empty_list(self):
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        self.assertEqual(inv["cloudRoles"], [])


# ---------------------------------------------------------------------------
# End-to-end: feed the synthesised inventory into the v3 engine.
# ---------------------------------------------------------------------------

class EngineV3RoundTrip(unittest.TestCase):
    """Build a v3 inventory from our fakes and confirm the v3 engine accepts
    it without error. The engine's correctness is pinned by
    ``argus.engine_v3.test_engine``; here we only check end-to-end
    compatibility of the collector's output."""

    def test_engine_analyse_consumes_collector_output(self):
        from argus.engine_v3 import engine, threat_intel
        inv = build_inventory(_scenario_apis(), "prod-eu-1")
        # Minimal scanner-style finding so the engine has something to score.
        findings = [{
            "id": "F-001", "source": "trivy", "type": "cve",
            "cve": "CVE-2026-31337", "cvss": 9.8, "severity": "critical",
            "target": "payments/invoice-api",
            "title": "RCE in libfoo < 2.1",
        }]
        # Use override-only intel so this test doesn't depend on the network.
        intel = threat_intel.refresh(cves_for_epss=None, allow_network=False)
        report = engine.analyse(inv, findings, intel)
        self.assertIn("riskScore", report)
        self.assertIn("chokePoints", report)
        self.assertIn("findings", report)
        # The vulnerable workload is internet-exposed → score is non-trivial.
        f = next(f for f in report["findings"] if f["id"] == "F-001")
        self.assertEqual(f["target"], "payments/invoice-api")


if __name__ == "__main__":
    unittest.main()
