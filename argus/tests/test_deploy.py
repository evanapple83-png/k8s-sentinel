"""Phase 4 RBAC guardrail tests. The whole point of ARGUS shipping a read-only
RBAC is that the cluster operator can audit ``deploy/rbac.yaml`` in seconds and
know there is no way for the scanner to read Secret data or change cluster
state. These tests pin that contract: if anyone adds ``secrets`` or a write
verb to the ClusterRole, this fails before it ever ships.
"""
from __future__ import annotations

import os
import sys
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

RBAC_PATH = os.path.join(REPO_ROOT, "deploy", "rbac.yaml")
JOB_PATH = os.path.join(REPO_ROOT, "deploy", "job.yaml")
CRONJOB_PATH = os.path.join(REPO_ROOT, "deploy", "cronjob.yaml")

# Verbs we will accept anywhere in argus-readonly.
_ALLOWED_VERBS = {"get", "list", "watch"}

# Resources that, if listed, would let ARGUS read Secret content. These must
# never appear on argus-readonly under any apiGroup.
_FORBIDDEN_RESOURCES = {
    "secrets",
    "pods/exec",
    "pods/portforward",
    "pods/proxy",
    "pods/attach",
    "nodes",
    "nodes/proxy",
    "nodes/stats",
}


def _load_yaml_documents(path: str) -> list:
    with open(path) as f:
        return [doc for doc in yaml.safe_load_all(f) if doc]


def _find(docs, kind, name):
    for doc in docs:
        if doc.get("kind") == kind and (doc.get("metadata") or {}).get("name") == name:
            return doc
    return None


class RbacReadOnlyContract(unittest.TestCase):
    """Hard invariants over the shipped ClusterRole."""

    @classmethod
    def setUpClass(cls):
        cls.docs = _load_yaml_documents(RBAC_PATH)
        cls.cluster_role = _find(cls.docs, "ClusterRole", "argus-readonly")
        assert cls.cluster_role, "argus-readonly ClusterRole missing from deploy/rbac.yaml"

    def test_only_get_list_watch_verbs_anywhere(self):
        offenders = []
        for rule in self.cluster_role["rules"]:
            for verb in rule.get("verbs") or []:
                if verb not in _ALLOWED_VERBS:
                    offenders.append((rule.get("resources"), verb))
        self.assertEqual(offenders, [],
                         f"argus-readonly must only grant get/list/watch — found {offenders}")

    def test_no_forbidden_resources(self):
        offenders = []
        for rule in self.cluster_role["rules"]:
            for resource in rule.get("resources") or []:
                if resource in _FORBIDDEN_RESOURCES:
                    offenders.append((rule.get("apiGroups"), resource))
        self.assertEqual(offenders, [],
                         f"argus-readonly must never include {_FORBIDDEN_RESOURCES}; "
                         f"found {offenders}")

    def test_no_wildcard_resources_or_verbs(self):
        offenders = []
        for rule in self.cluster_role["rules"]:
            for resource in rule.get("resources") or []:
                if resource == "*":
                    offenders.append(("resource", rule))
            for verb in rule.get("verbs") or []:
                if verb == "*":
                    offenders.append(("verb", rule))
            for group in rule.get("apiGroups") or []:
                if group == "*":
                    offenders.append(("apiGroup", rule))
        self.assertEqual(offenders, [],
                         "argus-readonly must list resources/verbs/apiGroups explicitly; "
                         f"found wildcards: {offenders}")

    def test_clusterrolebinding_targets_argus_sa(self):
        binding = _find(self.docs, "ClusterRoleBinding", "argus-readonly")
        self.assertIsNotNone(binding)
        self.assertEqual(binding["roleRef"]["name"], "argus-readonly")
        self.assertEqual(binding["roleRef"]["kind"], "ClusterRole")
        subjects = binding["subjects"]
        self.assertEqual(len(subjects), 1)
        self.assertEqual(subjects[0]["kind"], "ServiceAccount")
        self.assertEqual(subjects[0]["name"], "argus")
        self.assertEqual(subjects[0]["namespace"], "argus-system")


class JobsAreHardened(unittest.TestCase):
    """The Job and CronJob both have to inherit the read-only stance — running
    as nonroot, with no privilege escalation, no host namespaces, and a
    read-only root filesystem. If any of these regress, this test fails."""

    def _container(self, manifest_path, kind):
        docs = _load_yaml_documents(manifest_path)
        wf = next(d for d in docs if d.get("kind") == kind)
        if kind == "Job":
            tmpl = wf["spec"]["template"]
        else:
            tmpl = wf["spec"]["jobTemplate"]["spec"]["template"]
        return tmpl["spec"], tmpl["spec"]["containers"][0]

    def _assert_hardened(self, pod_spec, container):
        # Pod-level
        sec = pod_spec.get("securityContext", {})
        self.assertTrue(sec.get("runAsNonRoot"), "pod securityContext.runAsNonRoot must be true")
        self.assertGreater(sec.get("runAsUser") or 0, 0)
        # Container-level
        csec = container.get("securityContext", {})
        self.assertTrue(csec.get("runAsNonRoot"))
        self.assertTrue(csec.get("readOnlyRootFilesystem"))
        self.assertFalse(csec.get("allowPrivilegeEscalation", True))
        caps = (csec.get("capabilities") or {}).get("drop") or []
        self.assertIn("ALL", caps, "container must drop ALL capabilities")
        # Host namespaces
        for forbidden in ("hostNetwork", "hostPID", "hostIPC"):
            self.assertFalse(pod_spec.get(forbidden), f"{forbidden} must not be set")
        # Uses the argus SA
        self.assertEqual(pod_spec.get("serviceAccountName"), "argus")
        # Image is parameterised, but the args must include the read-only --in-cluster path.
        self.assertIn("--in-cluster", container["args"])

    def test_job_is_hardened(self):
        pod, ctr = self._container(JOB_PATH, "Job")
        self._assert_hardened(pod, ctr)

    def test_cronjob_is_hardened(self):
        pod, ctr = self._container(CRONJOB_PATH, "CronJob")
        self._assert_hardened(pod, ctr)


if __name__ == "__main__":
    unittest.main()
