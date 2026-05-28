"""Phase 5 smoke-artifact tests. We can't run kind in unit tests, but we can
pin the shape of ``test/vulnerable-workloads.yaml`` so the smoke script is
guaranteed to produce the attack-path-emitting cluster state it expects.
"""
from __future__ import annotations

import os
import sys
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

SMOKE_YAML = os.path.join(REPO_ROOT, "test", "vulnerable-workloads.yaml")
SMOKE_SH = os.path.join(REPO_ROOT, "scripts", "smoke.sh")


def _docs() -> list:
    with open(SMOKE_YAML) as f:
        return [d for d in yaml.safe_load_all(f) if d]


def _find(docs, kind, name, namespace=None):
    for d in docs:
        meta = d.get("metadata", {})
        if d.get("kind") == kind and meta.get("name") == name:
            if namespace is None or meta.get("namespace") == namespace:
                return d
    return None


class SmokeFixtureShape(unittest.TestCase):
    """The vulnerable cluster must contain the four ingredients the engine
    correlates into an attack path: a running workload, public exposure (an
    Ingress backed by a Service that selects the pods), runs-as-root, and an
    SA that can read Secrets in the namespace."""

    @classmethod
    def setUpClass(cls):
        cls.docs = _docs()
        cls.ns = "argus-smoke"

    def test_namespace_is_declared(self):
        ns = _find(self.docs, "Namespace", self.ns)
        self.assertIsNotNone(ns)

    def test_vulnerable_workload_runs_as_root(self):
        d = _find(self.docs, "Deployment", "vulnerable-web", self.ns)
        self.assertIsNotNone(d)
        ctr = d["spec"]["template"]["spec"]["containers"][0]
        sc = ctr.get("securityContext", {})
        # Either explicit root, or no override (default = root).
        self.assertFalse(sc.get("runAsNonRoot", False))
        self.assertEqual(sc.get("runAsUser", 0), 0)

    def test_vulnerable_workload_is_exposed_via_ingress(self):
        svc = _find(self.docs, "Service", "vulnerable-web", self.ns)
        ing = _find(self.docs, "Ingress", "vulnerable-web", self.ns)
        self.assertIsNotNone(svc)
        self.assertIsNotNone(ing)
        # The Service selector must match the Deployment's pod labels.
        d = _find(self.docs, "Deployment", "vulnerable-web", self.ns)
        labels = d["spec"]["template"]["metadata"]["labels"]
        self.assertTrue(all(labels.get(k) == v for k, v in svc["spec"]["selector"].items()))
        # The Ingress must route to that Service.
        backends = []
        for rule in ing["spec"]["rules"]:
            for path in rule["http"]["paths"]:
                backends.append(path["backend"]["service"]["name"])
        self.assertIn("vulnerable-web", backends)

    def test_vulnerable_sa_can_read_secrets_in_namespace(self):
        sa = _find(self.docs, "ServiceAccount", "vuln-app", self.ns)
        role = _find(self.docs, "Role", "secret-reader", self.ns)
        rb = _find(self.docs, "RoleBinding", "vuln-app-secret-reader", self.ns)
        self.assertIsNotNone(sa)
        self.assertIsNotNone(role)
        self.assertIsNotNone(rb)

        secret_rule = next(
            (r for r in role["rules"] if "secrets" in (r.get("resources") or [])),
            None,
        )
        self.assertIsNotNone(secret_rule, "secret-reader Role must list 'secrets'")
        self.assertTrue(set(secret_rule["verbs"]) & {"get", "list"})
        # Binding wires the SA to the role.
        self.assertEqual(rb["roleRef"]["name"], "secret-reader")
        subj = rb["subjects"][0]
        self.assertEqual(subj["kind"], "ServiceAccount")
        self.assertEqual(subj["name"], "vuln-app")

    def test_benign_workload_is_hardened_and_not_exposed(self):
        d = _find(self.docs, "Deployment", "benign-internal", self.ns)
        self.assertIsNotNone(d)
        ctr = d["spec"]["template"]["spec"]["containers"][0]
        sc = ctr.get("securityContext", {})
        self.assertTrue(sc.get("runAsNonRoot"))
        self.assertFalse(sc.get("allowPrivilegeEscalation", True))
        self.assertTrue(sc.get("readOnlyRootFilesystem"))
        self.assertIn("ALL", (sc.get("capabilities") or {}).get("drop") or [])
        # No service / ingress points at the benign workload.
        for kind in ("Service", "Ingress"):
            for doc in self.docs:
                if doc.get("kind") != kind:
                    continue
                spec = doc.get("spec") or {}
                if kind == "Service":
                    selector = spec.get("selector") or {}
                    self.assertNotEqual(selector.get("app"), "benign-internal")
                else:
                    for rule in spec.get("rules") or []:
                        for path in (rule.get("http") or {}).get("paths") or []:
                            self.assertNotEqual(
                                path["backend"]["service"]["name"], "benign-internal"
                            )

    def test_benign_workload_has_deny_external_networkpolicy(self):
        np = _find(self.docs, "NetworkPolicy", "benign-internal-deny-external", self.ns)
        self.assertIsNotNone(np)
        spec = np["spec"]
        self.assertEqual(spec["podSelector"]["matchLabels"], {"app": "benign-internal"})
        self.assertIn("Ingress", spec.get("policyTypes", []))
        # Empty/missing ingress rules => deny-external (matches engine shape).
        self.assertFalse(spec.get("ingress"))


class SmokeScriptShape(unittest.TestCase):
    """Sanity checks on the shell script — pins critical behaviour without
    actually running it."""

    @classmethod
    def setUpClass(cls):
        with open(SMOKE_SH) as f:
            cls.text = f.read()

    def test_uses_set_euo_pipefail(self):
        self.assertIn("set -euo pipefail", self.text)

    def test_requires_read_only_prerequisites(self):
        for tool in ("kind", "kubectl", "python3", "trivy"):
            self.assertIn(f'need {tool}', self.text)

    def test_applies_both_rbac_and_seed_manifests(self):
        self.assertIn("deploy/rbac.yaml", self.text)
        self.assertIn("test/vulnerable-workloads.yaml", self.text)

    def test_uses_argus_sa_token_not_cluster_admin(self):
        self.assertIn("create token argus", self.text)
        self.assertNotIn("cluster-admin", self.text)


if __name__ == "__main__":
    unittest.main()
