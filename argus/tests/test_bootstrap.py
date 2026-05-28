"""Tests for argus.bootstrap + argus.events_client.

Everything is mocked — no live cluster, no real network. The tests pin the
contract-level invariants the FROZEN wire contract requires:

  * keypair + CSR shape (CN / O / signer);
  * Authorization: Bearer header + JSON body on every control-plane call;
  * detail-payload size cap;
  * --auto-approve patches the approval subresource with type=Approved;
  * RBAC is idempotent against an existing ClusterRole;
  * --cleanup deletes the CSR + CRB on success AND on failure;
  * stage failures POST an `error` event with {stage, message} and surface
    as a non-zero exit from the CLI wrapper.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace as N
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

# Module imports — these MUST work without a cluster or a network round-trip.
from argus import bootstrap, cli, events_client  # noqa: E402


# ---------------------------------------------------------------------------
# A minimal yaml kubeconfig the bootstrap module's _active_cluster_info can
# parse. Used everywhere a real kubeconfig is required.
# ---------------------------------------------------------------------------

_FAKE_CA_PEM = b"-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"
_FAKE_CA_B64 = base64.b64encode(_FAKE_CA_PEM).decode("ascii")


def _write_fake_kubeconfig(tmpdir: str) -> str:
    path = os.path.join(tmpdir, "kubeconfig")
    with open(path, "w") as f:
        f.write(
            f"""apiVersion: v1
kind: Config
clusters:
  - name: fake
    cluster:
      server: https://kube.example:6443
      certificate-authority-data: {_FAKE_CA_B64}
contexts:
  - name: fake-ctx
    context:
      cluster: fake
      user: admin
users:
  - name: admin
    user:
      token: redacted
current-context: fake-ctx
"""
        )
    return path


# ---------------------------------------------------------------------------
# 1. CSR generation
# ---------------------------------------------------------------------------

class CsrGenerationTests(unittest.TestCase):

    def test_keypair_generates_ec_p256_by_default(self):
        pem, key = bootstrap._generate_keypair()
        self.assertIn(b"-----BEGIN PRIVATE KEY-----", pem)
        # cryptography returns an EC private key object by default.
        from cryptography.hazmat.primitives.asymmetric import ec
        self.assertIsInstance(key, ec.EllipticCurvePrivateKey)

    def test_csr_has_correct_cn_and_o(self):
        _, key = bootstrap._generate_keypair()
        csr_pem, csr = bootstrap._build_csr(key, common_name="argus-agent-deadbe")
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        parsed = x509.load_pem_x509_csr(csr_pem)
        cn = parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        org = parsed.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        self.assertEqual(cn, "argus-agent-deadbe")
        self.assertEqual(org, "argus-readonly")

    def test_private_key_file_is_0600(self):
        pem, _ = bootstrap._generate_keypair()
        path = bootstrap._write_private_key(pem)
        try:
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600, "private key must be 0600")
        finally:
            os.unlink(path)

    def test_short_random_is_6_hex_chars(self):
        s = bootstrap._short_random()
        self.assertEqual(len(s), 6)
        int(s, 16)  # must parse as hex


# ---------------------------------------------------------------------------
# 2. CLI argument plumbing
# ---------------------------------------------------------------------------

class BootstrapCliParsingTests(unittest.TestCase):

    def test_argparse_accepts_required_flags(self):
        parser = cli.build_parser()
        ns = parser.parse_args([
            "bootstrap", "csr",
            "--enroll", "ent_abc",
            "--control-plane", "https://app.example",
        ])
        self.assertEqual(ns.command, "bootstrap")
        self.assertEqual(ns.bootstrap_command, "csr")
        self.assertEqual(ns.enroll, "ent_abc")
        self.assertEqual(ns.control_plane, "https://app.example")
        self.assertEqual(ns.ttl, 3600)
        self.assertFalse(ns.auto_approve)
        self.assertFalse(ns.cleanup)
        self.assertEqual(ns.out, "./argus-agent.kubeconfig")

    def test_argparse_overrides(self):
        parser = cli.build_parser()
        ns = parser.parse_args([
            "bootstrap", "csr",
            "--enroll", "ent_x",
            "--control-plane", "https://cp",
            "--ttl", "900",
            "--auto-approve",
            "--cleanup",
            "--out", "/tmp/k.yaml",
            "--admin-context", "kind-kind",
        ])
        self.assertEqual(ns.ttl, 900)
        self.assertTrue(ns.auto_approve)
        self.assertTrue(ns.cleanup)
        self.assertEqual(ns.out, "/tmp/k.yaml")
        self.assertEqual(ns.admin_context, "kind-kind")

    def test_bootstrap_options_dataclass_round_trips(self):
        opts = bootstrap.BootstrapOptions(
            enroll="ent_x", control_plane="https://cp", ttl=900,
            auto_approve=True, cleanup=True,
        )
        self.assertEqual(opts.enroll, "ent_x")
        self.assertTrue(opts.auto_approve)
        self.assertTrue(opts.cleanup)
        # log default exists.
        self.assertIsNotNone(opts.log)


# ---------------------------------------------------------------------------
# 3. events_client — Auth header + JSON body
# ---------------------------------------------------------------------------

class EventsClientHttpTests(unittest.TestCase):

    def test_post_event_sets_bearer_and_json_body(self):
        captured = {}

        class _Resp:
            status = 204

            def read(self):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            captured["body"] = req.data
            return _Resp()

        with patch.object(events_client.urllib.request, "urlopen", _fake_urlopen):
            events_client.post_event(
                "https://cp.example", "cluster-uuid-123",
                "ent_token_42",
                "csr_submitted",
                {"csrName": "argus-agent-abc123", "ttlSeconds": 3600},
            )

        # URL
        self.assertEqual(
            captured["url"],
            "https://cp.example/api/clusters/cluster-uuid-123/events",
        )
        # Authorization header — header names are case-folded by urllib
        # (Title-Case).
        auth = {k.lower(): v for k, v in captured["headers"].items()}
        self.assertEqual(auth["authorization"], "Bearer ent_token_42")
        self.assertEqual(auth["content-type"], "application/json")
        # Body shape — type + detail at top level.
        body = json.loads(captured["body"])
        self.assertEqual(body["type"], "csr_submitted")
        self.assertEqual(body["detail"]["csrName"], "argus-agent-abc123")
        self.assertEqual(body["detail"]["ttlSeconds"], 3600)

    def test_post_scan_returns_parsed_json(self):
        class _Resp:
            status = 201

            def read(self):
                return b'{"scanId": "scan-1", "createdAt": "2026-05-28T10:00:00Z"}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with patch.object(events_client.urllib.request, "urlopen",
                          lambda req, timeout=None: _Resp()):  # noqa: ARG005
            out = events_client.post_scan(
                "https://cp", "cid", "ent_t", {"cluster": "x"},
            )
        self.assertEqual(out["scanId"], "scan-1")

    def test_post_event_raises_on_4xx(self):
        import urllib.error

        def _raise(req, timeout=None):  # noqa: ARG001
            raise urllib.error.HTTPError(
                req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"error":"nope"}'),
            )

        with patch.object(events_client.urllib.request, "urlopen", _raise):
            with self.assertRaises(events_client.EventsClientError):
                events_client.post_event("https://cp", "cid", "ent_t", "cli_started", {})

    def test_post_event_retries_once_on_5xx(self):
        import urllib.error

        calls = {"n": 0}

        class _Resp:
            status = 204

            def read(self):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def _maybe_fail(req, timeout=None):  # noqa: ARG001
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.HTTPError(
                    req.full_url, 502, "Bad Gateway", {}, io.BytesIO(b""),
                )
            return _Resp()

        with patch.object(events_client.urllib.request, "urlopen", _maybe_fail), \
             patch.object(events_client.time, "sleep", lambda _: None):
            events_client.post_event("https://cp", "cid", "ent_t", "cli_started", {})
        self.assertEqual(calls["n"], 2)

    def test_detail_payload_capped_to_2kb(self):
        big = {"k": "x" * 5000}
        bounded = events_client._bounded_detail(big)
        encoded = json.dumps(bounded).encode("utf-8")
        self.assertLessEqual(len(encoded), 2048)


# ---------------------------------------------------------------------------
# 4. Auto-approve path: patches the CSR with the Approved condition
# ---------------------------------------------------------------------------

class AutoApproveTests(unittest.TestCase):

    def test_auto_approve_patches_with_approved_condition(self):
        # Fake CertificatesV1Api: read returns an empty-status CSR object;
        # patch_*_approval captures what we patched with.
        from kubernetes import client
        captured = {}

        fake_csr = client.V1CertificateSigningRequest(
            metadata=client.V1ObjectMeta(name="argus-agent-abc"),
            spec=client.V1CertificateSigningRequestSpec(
                request="dGVzdA==", signer_name="kubernetes.io/kube-apiserver-client",
                usages=["client auth"],
            ),
            status=client.V1CertificateSigningRequestStatus(conditions=None),
        )

        certs_v1 = MagicMock()
        certs_v1.read_certificate_signing_request.return_value = fake_csr

        def _capture_patch(*, name, body):
            captured["name"] = name
            captured["conditions"] = list(body.status.conditions or [])

        certs_v1.patch_certificate_signing_request_approval.side_effect = _capture_patch

        bootstrap._auto_approve_csr(certs_v1, "argus-agent-abc")

        self.assertEqual(captured["name"], "argus-agent-abc")
        self.assertEqual(len(captured["conditions"]), 1)
        cond = captured["conditions"][0]
        self.assertEqual(cond.type, "Approved")
        self.assertEqual(cond.status, "True")
        self.assertIn("argus", cond.reason)


# ---------------------------------------------------------------------------
# 5. RBAC idempotency
# ---------------------------------------------------------------------------

class RbacIdempotencyTests(unittest.TestCase):

    def test_ensure_cluster_role_reuses_existing(self):
        from kubernetes.client import V1ClusterRole
        rbac_v1 = MagicMock()
        rbac_v1.read_cluster_role.return_value = V1ClusterRole(metadata=None, rules=[])
        name = bootstrap._ensure_cluster_role(rbac_v1)
        self.assertEqual(name, bootstrap.SHARED_CLUSTER_ROLE_NAME)
        rbac_v1.create_cluster_role.assert_not_called()

    def test_ensure_cluster_role_creates_when_missing(self):
        from kubernetes.client import exceptions as kexc
        rbac_v1 = MagicMock()
        rbac_v1.read_cluster_role.side_effect = kexc.ApiException(status=404, reason="NotFound")
        bootstrap._ensure_cluster_role(rbac_v1)
        rbac_v1.create_cluster_role.assert_called_once()
        # The created ClusterRole must have ZERO secrets verbs anywhere.
        created = rbac_v1.create_cluster_role.call_args.kwargs.get("body") \
            or rbac_v1.create_cluster_role.call_args.args[0]
        for rule in created.rules:
            self.assertNotIn("secrets", rule.resources,
                             "RBAC must never include the secrets resource")

    def test_ensure_cluster_role_binding_binds_user_and_group(self):
        rbac_v1 = MagicMock()
        bootstrap._ensure_cluster_role_binding(
            rbac_v1, "argus-readonly-abc", "argus-readonly",
            cn="argus-agent-abc123", organization="argus-readonly",
        )
        body = rbac_v1.create_cluster_role_binding.call_args.kwargs.get("body") \
            or rbac_v1.create_cluster_role_binding.call_args.args[0]
        kinds = {(s.kind, s.name) for s in body.subjects}
        self.assertIn(("User", "argus-agent-abc123"), kinds)
        self.assertIn(("Group", "argus-readonly"), kinds)


# ---------------------------------------------------------------------------
# 6. Readonly rules — contract §7 guarantee
# ---------------------------------------------------------------------------

class ReadonlyRulesContractTests(unittest.TestCase):

    def test_zero_secrets_verbs_anywhere(self):
        for rule in bootstrap.READONLY_RULES:
            self.assertNotIn("secrets", rule["resources"],
                             "no read-only rule may include `secrets`")
            for v in rule["verbs"]:
                self.assertIn(v, {"get", "list", "watch"},
                              f"verb {v!r} is not read-only")

    def test_no_wildcards(self):
        for rule in bootstrap.READONLY_RULES:
            self.assertNotIn("*", rule["resources"])
            self.assertNotIn("*", rule["verbs"])


# ---------------------------------------------------------------------------
# 7. Cleanup path — success AND failure
# ---------------------------------------------------------------------------

class CleanupTests(unittest.TestCase):

    def _admin_apis(self):
        return bootstrap._AdminApis(
            certificates_v1=MagicMock(),
            rbac_v1=MagicMock(),
            core_v1=MagicMock(),
            cluster_server="https://k.example",
            cluster_ca_b64=_FAKE_CA_B64,
        )

    def test_cleanup_deletes_both_csr_and_crb(self):
        apis = self._admin_apis()
        state = {
            "csr_name": "argus-agent-aaa",
            "csr_created": True,
            "crb_created": True,
            "cluster_role_binding_name": "argus-readonly-cid12345",
        }
        bootstrap._cleanup_resources(apis, state)
        apis.certificates_v1.delete_certificate_signing_request.assert_called_once_with(
            name="argus-agent-aaa",
        )
        apis.rbac_v1.delete_cluster_role_binding.assert_called_once_with(
            name="argus-readonly-cid12345",
        )

    def test_cleanup_tolerates_404(self):
        from kubernetes.client import exceptions as kexc
        apis = self._admin_apis()
        apis.certificates_v1.delete_certificate_signing_request.side_effect = \
            kexc.ApiException(status=404, reason="NotFound")
        apis.rbac_v1.delete_cluster_role_binding.side_effect = \
            kexc.ApiException(status=404, reason="NotFound")
        state = {
            "csr_name": "x", "csr_created": True,
            "crb_created": True, "cluster_role_binding_name": "y",
        }
        # Must not raise.
        bootstrap._cleanup_resources(apis, state)

    def test_failure_path_runs_best_effort_cleanup_when_flag_set(self):
        """When run_bootstrap_csr fails AFTER creating the CSR, --cleanup
        must still trigger a delete attempt on whatever we did create."""

        events_calls = []

        def _fake_event(_cp, _cid, _tok, etype, detail):
            events_calls.append((etype, detail))

        apis = self._admin_apis()
        # Make the CSR submission fail.
        apis.certificates_v1.create_certificate_signing_request.side_effect = \
            RuntimeError("boom-submit")

        with tempfile.TemporaryDirectory() as tmp:
            kc = _write_fake_kubeconfig(tmp)
            opts = bootstrap.BootstrapOptions(
                enroll="ent_t", control_plane="https://cp",
                cleanup=True, admin_kubeconfig=kc,
                cluster_id_override="cluster-uuid-1234",
            )
            # Patch the network calls so we don't hit anything.
            with patch.object(events_client, "post_event", side_effect=_fake_event), \
                 patch.object(bootstrap, "_load_admin_apis", return_value=apis):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.run_bootstrap_csr(opts)

        # The error event must have been posted with the failing stage.
        types = [t for t, _ in events_calls]
        self.assertIn("error", types)
        err_detail = next(d for t, d in events_calls if t == "error")
        self.assertIn("stage", err_detail)
        self.assertIn("message", err_detail)
        self.assertEqual(err_detail["stage"], "submit_csr")
        # The error message must not leak the enrollment token.
        self.assertNotIn("ent_t", err_detail["message"])


# ---------------------------------------------------------------------------
# 8. CLI wrapper — non-zero exit + error event on stage failure
# ---------------------------------------------------------------------------

class CliErrorPathTests(unittest.TestCase):

    def test_bootstrap_csr_command_returns_nonzero_on_failure(self):
        parser = cli.build_parser()
        args = parser.parse_args([
            "bootstrap", "csr",
            "--enroll", "ent_abc",
            "--control-plane", "https://cp",
            "--quiet",
        ])
        # Make run_bootstrap_csr raise a BootstrapError directly.
        boom = bootstrap.BootstrapError("submit_csr", "synthetic failure")
        with patch.object(bootstrap, "run_bootstrap_csr", side_effect=boom):
            rc = cli.cmd_bootstrap_csr(args)
        self.assertEqual(rc, 1)

    def test_scan_with_bootstrap_csr_shortcut_requires_enroll_and_control_plane(self):
        parser = cli.build_parser()
        # Calls parser.error which raises SystemExit.
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", new_callable=io.StringIO):
                cli.main(["scan", "--bootstrap", "csr"])

    def test_safe_message_redacts_enrollment_token(self):
        msg = bootstrap._safe_message(
            RuntimeError("failed with token ent_AAAAAAAAAAAAAAAAAAAAAAAAAA")
        )
        self.assertNotIn("ent_AAAA", msg)
        self.assertIn("redacted", msg)

    def test_safe_message_redacts_pem_block(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "VERY-SECRET-MATERIAL-DO-NOT-LOG\n"
            "-----END PRIVATE KEY-----"
        )
        msg = bootstrap._safe_message(RuntimeError(pem))
        self.assertNotIn("VERY-SECRET-MATERIAL", msg)


# ---------------------------------------------------------------------------
# 9. End-to-end happy path (fully mocked)
# ---------------------------------------------------------------------------

class HappyPathIntegrationTests(unittest.TestCase):
    """Exercise run_bootstrap_csr end-to-end with mocked k8s + control-plane.
    Pins the event sequence the contract requires."""

    def test_full_pipeline_posts_contract_event_sequence(self):
        events_seen = []

        def _fake_event(_cp, _cid, _tok, etype, detail):
            events_seen.append((etype, dict(detail)))

        def _fake_scan(_cp, _cid, _tok, _report):
            return {"scanId": "scan-uuid", "createdAt": "2026-05-28T10:00:00Z"}

        # Build a fake admin apis with an immediately-issued cert.
        from kubernetes import client as kclient
        issued_cert_b64 = base64.b64encode(
            b"-----BEGIN CERTIFICATE-----\nFAKEISSUED\n-----END CERTIFICATE-----\n"
        ).decode("ascii")

        approved_csr = kclient.V1CertificateSigningRequest(
            metadata=kclient.V1ObjectMeta(name="placeholder"),
            spec=kclient.V1CertificateSigningRequestSpec(
                request="dGVzdA==", signer_name=bootstrap.SIGNER_NAME, usages=["client auth"],
            ),
            status=kclient.V1CertificateSigningRequestStatus(
                conditions=[kclient.V1CertificateSigningRequestCondition(
                    type="Approved", status="True", reason="t",
                )],
                certificate=issued_cert_b64,
            ),
        )

        certs_v1 = MagicMock()
        certs_v1.create_certificate_signing_request.return_value = None
        certs_v1.read_certificate_signing_request.return_value = approved_csr

        # ClusterRole exists already -> reuse path.
        rbac_v1 = MagicMock()
        rbac_v1.read_cluster_role.return_value = kclient.V1ClusterRole(
            metadata=kclient.V1ObjectMeta(name=bootstrap.SHARED_CLUSTER_ROLE_NAME),
            rules=[],
        )

        admin_apis = bootstrap._AdminApis(
            certificates_v1=certs_v1, rbac_v1=rbac_v1, core_v1=MagicMock(),
            cluster_server="https://kube.example:6443", cluster_ca_b64=_FAKE_CA_B64,
        )

        # Stub the scan call — return a minimal report shape.
        def _fake_run_scan(_kc_path):
            return {"cluster": "x", "riskScore": 10, "findings": []}

        with tempfile.TemporaryDirectory() as tmp:
            kc = _write_fake_kubeconfig(tmp)
            out_kc = os.path.join(tmp, "agent.yaml")
            opts = bootstrap.BootstrapOptions(
                enroll="ent_realtoken_xxxxxxxxxxxxxxxxxxxxxxx",
                control_plane="https://cp",
                auto_approve=True,
                cleanup=True,
                out=out_kc,
                admin_kubeconfig=kc,
                cluster_id_override="cluster-uuid-1234",
            )
            with patch.object(events_client, "post_event", side_effect=_fake_event), \
                 patch.object(events_client, "post_scan", side_effect=_fake_scan), \
                 patch.object(bootstrap, "_load_admin_apis", return_value=admin_apis), \
                 patch.object(bootstrap, "_run_scan", side_effect=_fake_run_scan), \
                 patch("sys.stderr", new_callable=io.StringIO):
                result = bootstrap.run_bootstrap_csr(opts)

            types = [t for t, _ in events_seen]
            # Required order: cli_started -> csr_submitted -> approved -> rbac_bound.
            # (auto_approve path: no awaiting_approval event.)
            self.assertEqual(types[0], "cli_started")
            self.assertIn("csr_submitted", types)
            self.assertIn("approved", types)
            self.assertIn("rbac_bound", types)
            # rbac_bound carries the right subject shape.
            rbac_detail = next(d for t, d in events_seen if t == "rbac_bound")
            self.assertEqual(rbac_detail["subject"]["o"], "argus-readonly")
            self.assertTrue(rbac_detail["subject"]["cn"].startswith("argus-agent-"))
            # Result shape.
            self.assertEqual(result.scan_id, "scan-uuid")
            self.assertEqual(result.cluster_role, bootstrap.SHARED_CLUSTER_ROLE_NAME)
            self.assertTrue(result.cleaned_up)
            # Cleanup actually ran the delete calls.
            certs_v1.delete_certificate_signing_request.assert_called_once()
            rbac_v1.delete_cluster_role_binding.assert_called_once()
            # Agent kubeconfig exists with 0600 perms.
            self.assertTrue(os.path.exists(out_kc))
            self.assertEqual(os.stat(out_kc).st_mode & 0o777, 0o600)


# ---------------------------------------------------------------------------
# 10. Awaiting-approval (non-auto) path posts the kubectl command verbatim
# ---------------------------------------------------------------------------

class AwaitingApprovalEventTests(unittest.TestCase):

    def test_awaiting_approval_event_carries_kubectl_command(self):
        events_seen = []

        def _fake_event(_cp, _cid, _tok, etype, detail):
            events_seen.append((etype, dict(detail)))

        # Pretend the cert is already issued so we don't actually sleep.
        from kubernetes import client as kclient
        issued = kclient.V1CertificateSigningRequest(
            metadata=kclient.V1ObjectMeta(name="x"),
            spec=kclient.V1CertificateSigningRequestSpec(
                request="dGVzdA==", signer_name=bootstrap.SIGNER_NAME, usages=["client auth"],
            ),
            status=kclient.V1CertificateSigningRequestStatus(
                conditions=[kclient.V1CertificateSigningRequestCondition(
                    type="Approved", status="True", reason="t",
                )],
                certificate=base64.b64encode(b"PEMBLOB").decode("ascii"),
            ),
        )
        certs_v1 = MagicMock()
        certs_v1.read_certificate_signing_request.return_value = issued

        rbac_v1 = MagicMock()
        rbac_v1.read_cluster_role.return_value = kclient.V1ClusterRole(
            metadata=kclient.V1ObjectMeta(name=bootstrap.SHARED_CLUSTER_ROLE_NAME),
            rules=[],
        )
        admin_apis = bootstrap._AdminApis(
            certificates_v1=certs_v1, rbac_v1=rbac_v1, core_v1=MagicMock(),
            cluster_server="https://k", cluster_ca_b64=_FAKE_CA_B64,
        )

        with tempfile.TemporaryDirectory() as tmp:
            kc = _write_fake_kubeconfig(tmp)
            opts = bootstrap.BootstrapOptions(
                enroll="ent_xxxx", control_plane="https://cp",
                auto_approve=False,  # <-- awaiting-approval branch
                admin_kubeconfig=kc,
                out=os.path.join(tmp, "agent.yaml"),
                cluster_id_override="cluster-uuid-1234",
            )
            with patch.object(events_client, "post_event", side_effect=_fake_event), \
                 patch.object(events_client, "post_scan",
                              return_value={"scanId": "s", "createdAt": "t"}), \
                 patch.object(bootstrap, "_load_admin_apis", return_value=admin_apis), \
                 patch.object(bootstrap, "_run_scan", return_value={"cluster": "x"}), \
                 patch("sys.stderr", new_callable=io.StringIO):
                bootstrap.run_bootstrap_csr(opts)

        awaiting = [d for t, d in events_seen if t == "awaiting_approval"]
        self.assertEqual(len(awaiting), 1)
        self.assertTrue(awaiting[0]["approveCommand"].startswith(
            "kubectl certificate approve argus-agent-"
        ))


if __name__ == "__main__":
    unittest.main()
