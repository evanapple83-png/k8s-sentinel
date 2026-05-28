"""argus/bootstrap.py — ``argus bootstrap csr`` flow.

Implements docs/PUBKEY_CONNECT_SPEC.md §4 + the FROZEN wire contract in
docs/PUBKEY_CONNECT_CONTRACT.md. The flow at a glance::

    1.  Generate EC P-256 (or RSA-2048) keypair locally in 0600 temp file.
    2.  Build a CSR (CN=argus-agent-<short>, O=argus-readonly).
    3.  POST cli_started event.
    4.  Submit a CertificateSigningRequest via the kube API.
    5.  Approval gate (auto-approve OR wait for `kubectl certificate approve`).
    6.  Apply read-only RBAC (reuse existing ClusterRole if present).
    7.  Decode cert; assemble scoped agent kubeconfig at --out.
    8.  Run the scan with the new kubeconfig.
    9.  POST /api/scans with { clusterId, report }.
   10.  Server emits scan_pushed event server-side (CLI doesn't post one).
   11.  Optional --cleanup removes the CSR + ClusterRoleBinding.

Every stage is wrapped in try/except — on failure we POST an ``error`` event
with ``{ stage, message }`` (with secret values stripped) and exit non-zero.
"""
from __future__ import annotations

import atexit
import base64
import json
import logging
import os
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from argus import events_client

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Read-only RBAC — MUST match contract §7. Zero secrets verbs anywhere.
# Mirrors deploy/helm/templates/rbac.yaml so the helm path and the pubkey
# path bind to identical authority.
# ---------------------------------------------------------------------------

READONLY_RULES: list[dict[str, list[str]]] = [
    {
        "api_groups": [""],
        "resources": [
            "pods", "services", "endpoints", "nodes", "namespaces",
            "serviceaccounts", "configmaps", "persistentvolumes",
            "persistentvolumeclaims", "replicationcontrollers",
        ],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["apps"],
        "resources": ["deployments", "daemonsets", "statefulsets", "replicasets"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["batch"],
        "resources": ["jobs", "cronjobs"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["networking.k8s.io"],
        "resources": ["networkpolicies", "ingresses"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["rbac.authorization.k8s.io"],
        "resources": ["roles", "rolebindings", "clusterroles", "clusterrolebindings"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["policy"],
        "resources": ["poddisruptionbudgets"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["apiextensions.k8s.io"],
        "resources": ["customresourcedefinitions"],
        "verbs": ["get", "list", "watch"],
    },
]


SHARED_CLUSTER_ROLE_NAME = "argus-readonly"
SIGNER_NAME = "kubernetes.io/kube-apiserver-client"
DEFAULT_TTL_SECONDS = 3600
APPROVAL_POLL_INTERVAL_S = 2.0
APPROVAL_POLL_TIMEOUT_S = 30 * 60  # 30 minutes — much longer than the cert TTL


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class BootstrapOptions:
    enroll: str
    control_plane: str
    ttl: int = DEFAULT_TTL_SECONDS
    auto_approve: bool = False
    cleanup: bool = False
    out: str = "./argus-agent.kubeconfig"
    admin_kubeconfig: Optional[str] = None
    admin_context: Optional[str] = None
    log: logging.Logger = field(default_factory=lambda: log)
    # The cluster_id is required for the scan POST. Resolution strategy
    # (in order):
    #   1. ARGUS_CLUSTER_ID env var (escape hatch).
    #   2. GET /api/clusters/_self with the enroll token (preferred).
    # See events_client.resolve_cluster_id for the rationale; the choice
    # is surfaced in the final report.
    cluster_id_override: Optional[str] = None


@dataclass
class BootstrapResult:
    cluster_id: str
    csr_name: str
    cluster_role: str
    cluster_role_binding: str
    kubeconfig_path: str
    scan_id: Optional[str]
    not_after: Optional[str]
    cleaned_up: bool


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def run_bootstrap_csr(opts: BootstrapOptions) -> BootstrapResult:
    """Run the full bootstrap → scan → push pipeline. Returns a
    :class:`BootstrapResult`; raises :class:`BootstrapError` on any failure
    (and the wrapper in :mod:`argus.cli` maps that to exit code 1 + posts
    an ``error`` event)."""
    logger = opts.log
    cluster_id = _resolve_cluster_id(opts)
    short = _short_random()
    csr_name = f"argus-agent-{short}"

    # The handles we need to clean up on the *failure* path.
    state: dict[str, Any] = {
        "key_path": None,
        "csr_name": csr_name,
        "csr_created": False,
        "crb_created": False,
        "cluster_role_name": SHARED_CLUSTER_ROLE_NAME,
        "cluster_role_created": False,
        "cluster_role_binding_name": f"argus-readonly-{_short_cluster_id(cluster_id)}",
    }

    try:
        # ---- 1. keypair + CSR ------------------------------------------
        with _stage("generate_keypair", opts, cluster_id):
            key_pem, key_obj = _generate_keypair()
            key_path = _write_private_key(key_pem)
            state["key_path"] = key_path
            csr_pem, csr_obj = _build_csr(key_obj, common_name=csr_name)

        # ---- 2. cli_started event --------------------------------------
        with _stage("cli_started", opts, cluster_id):
            events_client.post_event(
                opts.control_plane, cluster_id, opts.enroll,
                "cli_started",
                {"argusVersion": _argus_version(), "platform": sys.platform},
            )

        # ---- 3. submit CSR ---------------------------------------------
        admin_apis = _load_admin_apis(opts)
        with _stage("submit_csr", opts, cluster_id):
            _submit_csr(admin_apis.certificates_v1, csr_name, csr_pem, opts.ttl)
            state["csr_created"] = True
            events_client.post_event(
                opts.control_plane, cluster_id, opts.enroll,
                "csr_submitted",
                {"csrName": csr_name, "ttlSeconds": opts.ttl},
            )

        # ---- 4. approval gate ------------------------------------------
        approve_command = f"kubectl certificate approve {csr_name}"
        if opts.auto_approve:
            with _stage("auto_approve_csr", opts, cluster_id):
                _auto_approve_csr(admin_apis.certificates_v1, csr_name)
        else:
            with _stage("awaiting_approval", opts, cluster_id):
                events_client.post_event(
                    opts.control_plane, cluster_id, opts.enroll,
                    "awaiting_approval",
                    {"csrName": csr_name, "approveCommand": approve_command},
                )
                _print_approve_instructions(approve_command)

        with _stage("wait_for_issued_cert", opts, cluster_id):
            cert_pem_b64 = _wait_for_issued_cert(admin_apis.certificates_v1, csr_name)
            events_client.post_event(
                opts.control_plane, cluster_id, opts.enroll,
                "approved",
                {"csrName": csr_name},
            )

        # ---- 5. RBAC ---------------------------------------------------
        with _stage("apply_rbac", opts, cluster_id):
            role_name = _ensure_cluster_role(admin_apis.rbac_v1)
            state["cluster_role_name"] = role_name
            state["cluster_role_created"] = (role_name != SHARED_CLUSTER_ROLE_NAME)
            crb_name = state["cluster_role_binding_name"]
            _ensure_cluster_role_binding(
                admin_apis.rbac_v1, crb_name, role_name,
                cn=csr_name, organization="argus-readonly",
            )
            state["crb_created"] = True
            events_client.post_event(
                opts.control_plane, cluster_id, opts.enroll,
                "rbac_bound",
                {
                    "clusterRole": role_name,
                    "clusterRoleBinding": crb_name,
                    "subject": {"cn": csr_name, "o": "argus-readonly"},
                },
            )

        # ---- 6. assemble scoped kubeconfig -----------------------------
        with _stage("write_agent_kubeconfig", opts, cluster_id):
            cert_pem = base64.b64decode(cert_pem_b64).decode("utf-8")
            kubeconfig_yaml = _assemble_kubeconfig(
                opts, cert_pem=cert_pem, key_pem=key_pem.decode("utf-8"),
                user_name=csr_name,
            )
            _write_agent_kubeconfig(opts.out, kubeconfig_yaml)

        # ---- 7. run scan -----------------------------------------------
        with _stage("scan", opts, cluster_id):
            report = _run_scan(opts.out)

        # ---- 8. push report --------------------------------------------
        scan_id: Optional[str] = None
        with _stage("push_scan", opts, cluster_id):
            scan_resp = events_client.post_scan(
                opts.control_plane, cluster_id, opts.enroll, report,
            )
            scan_id = scan_resp.get("scanId")
            logger.info("Scan pushed: id=%s createdAt=%s",
                        scan_id, scan_resp.get("createdAt"))

        # ---- 9. NotAfter timestamp for the user ------------------------
        not_after = _extract_not_after(cert_pem)
        _print_expiry_warning(not_after)

        # ---- 10. optional cleanup --------------------------------------
        cleaned_up = False
        if opts.cleanup:
            with _stage("cleanup", opts, cluster_id):
                _cleanup_resources(admin_apis, state)
                cleaned_up = True

        return BootstrapResult(
            cluster_id=cluster_id,
            csr_name=csr_name,
            cluster_role=state["cluster_role_name"],
            cluster_role_binding=state["cluster_role_binding_name"],
            kubeconfig_path=opts.out,
            scan_id=scan_id,
            not_after=not_after,
            cleaned_up=cleaned_up,
        )
    except BootstrapError:
        # Already posted the error event inside _stage.
        if opts.cleanup:
            _best_effort_cleanup(opts, state)
        raise
    except Exception as e:  # noqa: BLE001
        # Defensive: anything we missed becomes a generic error.
        _post_error_event(opts, cluster_id, "unknown", _safe_message(e))
        if opts.cleanup:
            _best_effort_cleanup(opts, state)
        raise BootstrapError("unknown", str(e)) from e


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class BootstrapError(RuntimeError):
    """One of the bootstrap stages failed. ``stage`` carries the contract
    EventType detail.stage value."""

    def __init__(self, stage: str, message: str):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.message = message


# ---------------------------------------------------------------------------
# Stage wrapper — every stage's exceptions become an `error` event + raise.
# ---------------------------------------------------------------------------

class _stage:
    """Context manager that converts any exception into a
    BootstrapError, after posting an ``error`` event to the control-plane.

    Posting the event is best-effort — if the control-plane is unreachable
    we still want the local exception to surface."""

    def __init__(self, stage: str, opts: BootstrapOptions, cluster_id: str):
        self.stage = stage
        self.opts = opts
        self.cluster_id = cluster_id

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, _tb):
        if exc_value is None:
            return False
        msg = _safe_message(exc_value)
        _post_error_event(self.opts, self.cluster_id, self.stage, msg)
        # Re-raise as BootstrapError so the top-level handler exits cleanly.
        raise BootstrapError(self.stage, msg) from exc_value


def _post_error_event(opts: BootstrapOptions, cluster_id: str, stage: str, message: str) -> None:
    try:
        events_client.post_event(
            opts.control_plane, cluster_id, opts.enroll,
            "error",
            {"stage": stage, "message": message},
        )
    except Exception:  # noqa: BLE001
        opts.log.warning("Failed to POST error event for stage=%s", stage, exc_info=True)


def _safe_message(exc: BaseException) -> str:
    """Stringify an exception without leaking the enrollment token or any
    PEM-encoded material. Bounded to 400 chars (well under the 2 KB detail
    cap)."""
    s = str(exc) or exc.__class__.__name__
    # Defensive: never include "ent_" tokens or PEM blocks in event payloads.
    s = _scrub_secrets(s)
    return s[:400]


def _scrub_secrets(s: str) -> str:
    out = s
    # Redact enrollment-token-shaped strings.
    import re
    out = re.sub(r"ent_[A-Za-z0-9_-]{20,}", "ent_<redacted>", out)
    # Redact PEM blocks (key or cert).
    out = re.sub(
        r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----",
        "<pem-redacted>", out,
    )
    return out


# ---------------------------------------------------------------------------
# Keypair + CSR — cryptography library
# ---------------------------------------------------------------------------

def _generate_keypair():
    """Return (PEM-encoded private key bytes, key object). EC P-256 preferred;
    RSA-2048 fallback if EC isn't available for any reason."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    try:
        key = ec.generate_private_key(ec.SECP256R1())
    except Exception:  # noqa: BLE001
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem, key


def _build_csr(key_obj, *, common_name: str) -> tuple[bytes, Any]:
    """Build a CSR with CN=<common_name>, O=argus-readonly. Returns
    (PEM bytes, csr object)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "argus-readonly"),
        ]),
    )
    csr = builder.sign(key_obj, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM), csr


def _write_private_key(pem: bytes) -> str:
    """Write key bytes to a 0600 temp file and register cleanup with atexit.

    Returns the absolute path. The temp file lives in the OS temp dir with
    prefix ``argus-key-`` for greppability."""
    fh = tempfile.NamedTemporaryFile(
        mode="wb", prefix="argus-key-", suffix=".pem", delete=False,
    )
    try:
        fh.write(pem)
        fh.flush()
    finally:
        fh.close()
    os.chmod(fh.name, 0o600)
    atexit.register(_safe_unlink, fh.name)
    return fh.name


def _safe_unlink(path: str) -> None:
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Cluster API plumbing
# ---------------------------------------------------------------------------

@dataclass
class _AdminApis:
    certificates_v1: Any
    rbac_v1: Any
    core_v1: Any
    cluster_server: str
    cluster_ca_b64: str


def _load_admin_apis(opts: BootstrapOptions) -> _AdminApis:
    """Build the admin-kubeconfig-backed API clients and snapshot the
    cluster's server URL + CA — we need those to assemble the scoped
    kubeconfig later."""
    from kubernetes import client, config

    config.load_kube_config(
        config_file=opts.admin_kubeconfig, context=opts.admin_context,
    )
    # Snapshot the active cluster's server + CA from the loaded config.
    server, ca_b64 = _active_cluster_info(opts.admin_kubeconfig, opts.admin_context)
    return _AdminApis(
        certificates_v1=client.CertificatesV1Api(),
        rbac_v1=client.RbacAuthorizationV1Api(),
        core_v1=client.CoreV1Api(),
        cluster_server=server,
        cluster_ca_b64=ca_b64,
    )


def _active_cluster_info(kubeconfig_path: Optional[str], context: Optional[str]) -> tuple[str, str]:
    """Read the kubeconfig file and return (server, ca_data_base64) for the
    active (or specified) context."""
    path = kubeconfig_path or os.environ.get("KUBECONFIG") or os.path.expanduser("~/.kube/config")
    with open(path) as f:
        cfg = yaml.safe_load(f)
    ctx_name = context or cfg.get("current-context")
    contexts = {c["name"]: c["context"] for c in cfg.get("contexts") or []}
    if ctx_name not in contexts:
        raise RuntimeError(f"context {ctx_name!r} not found in {path}")
    cluster_name = contexts[ctx_name]["cluster"]
    clusters = {c["name"]: c["cluster"] for c in cfg.get("clusters") or []}
    if cluster_name not in clusters:
        raise RuntimeError(f"cluster {cluster_name!r} not found in {path}")
    cluster = clusters[cluster_name]
    server = cluster.get("server", "")
    ca_b64 = cluster.get("certificate-authority-data")
    if not ca_b64:
        ca_path = cluster.get("certificate-authority")
        if not ca_path:
            raise RuntimeError(f"cluster {cluster_name!r} has no CA — cannot assemble agent kubeconfig")
        with open(ca_path, "rb") as f:
            ca_b64 = base64.b64encode(f.read()).decode("ascii")
    return server, ca_b64


def _submit_csr(certs_v1, csr_name: str, csr_pem: bytes, ttl_seconds: int) -> None:
    from kubernetes import client

    body = client.V1CertificateSigningRequest(
        metadata=client.V1ObjectMeta(name=csr_name),
        spec=client.V1CertificateSigningRequestSpec(
            request=base64.b64encode(csr_pem).decode("ascii"),
            signer_name=SIGNER_NAME,
            usages=["client auth"],
            expiration_seconds=ttl_seconds,
        ),
    )
    certs_v1.create_certificate_signing_request(body=body)


def _auto_approve_csr(certs_v1, csr_name: str) -> None:
    """Append an Approved condition via the approval subresource."""
    from kubernetes import client
    import datetime

    csr = certs_v1.read_certificate_signing_request(name=csr_name)
    csr.status = csr.status or client.V1CertificateSigningRequestStatus()
    new_condition = client.V1CertificateSigningRequestCondition(
        type="Approved",
        status="True",
        reason="argus-auto-approve",
        message="Approved by argus bootstrap csr --auto-approve",
        last_update_time=datetime.datetime.now(datetime.timezone.utc),
    )
    existing = list(csr.status.conditions or [])
    existing.append(new_condition)
    csr.status.conditions = existing
    certs_v1.patch_certificate_signing_request_approval(name=csr_name, body=csr)


def _wait_for_issued_cert(certs_v1, csr_name: str) -> str:
    """Poll until ``status.conditions`` has type=Approved/status=True AND
    ``status.certificate`` is non-empty. Returns the base64-encoded cert."""
    deadline = time.monotonic() + APPROVAL_POLL_TIMEOUT_S
    last_log = 0.0
    while time.monotonic() < deadline:
        csr = certs_v1.read_certificate_signing_request(name=csr_name)
        status = getattr(csr, "status", None)
        conds = list(getattr(status, "conditions", None) or []) if status else []
        approved = any(
            (getattr(c, "type", None) == "Approved" and getattr(c, "status", None) == "True")
            for c in conds
        )
        denied = any(getattr(c, "type", None) == "Denied" for c in conds)
        failed = any(getattr(c, "type", None) == "Failed" for c in conds)
        if denied:
            raise RuntimeError(f"CSR {csr_name} was denied by the cluster")
        if failed:
            raise RuntimeError(f"CSR {csr_name} failed to be issued")
        cert = getattr(status, "certificate", None) if status else None
        if approved and cert:
            return cert if isinstance(cert, str) else cert.decode("ascii")
        # Throttled progress logging.
        now = time.monotonic()
        if now - last_log > 30:
            log.info("Waiting for CSR %s to be approved+issued…", csr_name)
            last_log = now
        time.sleep(APPROVAL_POLL_INTERVAL_S)
    raise TimeoutError(
        f"CSR {csr_name} not approved+issued within {APPROVAL_POLL_TIMEOUT_S}s"
    )


def _print_approve_instructions(approve_command: str) -> None:
    # ANSI green; falls back to plain text if NO_COLOR is set.
    if os.environ.get("NO_COLOR"):
        print(f"\nApprove the CSR with:\n    {approve_command}\n", file=sys.stderr)
    else:
        print(
            f"\n\033[1;32mApprove the CSR with:\n    {approve_command}\033[0m\n",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

def _ensure_cluster_role(rbac_v1) -> str:
    """If the shared ``argus-readonly`` ClusterRole already exists, reuse it.
    Otherwise create it. Returns the name we'll bind to."""
    from kubernetes import client
    from kubernetes.client import exceptions as kexc

    try:
        rbac_v1.read_cluster_role(name=SHARED_CLUSTER_ROLE_NAME)
        return SHARED_CLUSTER_ROLE_NAME
    except kexc.ApiException as e:
        if e.status != 404:
            raise

    rules = [
        client.V1PolicyRule(
            api_groups=r["api_groups"],
            resources=r["resources"],
            verbs=r["verbs"],
        )
        for r in READONLY_RULES
    ]
    cr = client.V1ClusterRole(
        metadata=client.V1ObjectMeta(name=SHARED_CLUSTER_ROLE_NAME),
        rules=rules,
    )
    rbac_v1.create_cluster_role(body=cr)
    return SHARED_CLUSTER_ROLE_NAME


def _ensure_cluster_role_binding(
    rbac_v1, name: str, role_name: str, *, cn: str, organization: str,
) -> None:
    """Bind the ClusterRole to BOTH the cert's CN (as User) and its O (as
    Group). Idempotent — replaces an existing CRB with the same name."""
    from kubernetes import client
    from kubernetes.client import exceptions as kexc

    subjects = [
        client.RbacV1Subject(
            kind="User", name=cn, api_group="rbac.authorization.k8s.io",
        ),
        client.RbacV1Subject(
            kind="Group", name=organization, api_group="rbac.authorization.k8s.io",
        ),
    ]
    role_ref = client.V1RoleRef(
        api_group="rbac.authorization.k8s.io",
        kind="ClusterRole",
        name=role_name,
    )
    body = client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name=name),
        role_ref=role_ref,
        subjects=subjects,
    )
    try:
        rbac_v1.create_cluster_role_binding(body=body)
    except kexc.ApiException as e:
        if e.status != 409:
            raise
        # Already exists — replace it so the subject is always exact.
        rbac_v1.replace_cluster_role_binding(name=name, body=body)


# ---------------------------------------------------------------------------
# Scoped agent kubeconfig
# ---------------------------------------------------------------------------

def _assemble_kubeconfig(
    opts: BootstrapOptions, *, cert_pem: str, key_pem: str, user_name: str,
) -> str:
    """Build a self-contained kubeconfig YAML the agent can use."""
    apis_for_cluster = _active_cluster_info(opts.admin_kubeconfig, opts.admin_context)
    server, ca_b64 = apis_for_cluster
    cluster_name = "argus-target"
    context_name = "argus"
    cfg = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": cluster_name,
                "cluster": {
                    "server": server,
                    "certificate-authority-data": ca_b64,
                },
            },
        ],
        "users": [
            {
                "name": user_name,
                "user": {
                    "client-certificate-data": base64.b64encode(cert_pem.encode("utf-8")).decode("ascii"),
                    "client-key-data": base64.b64encode(key_pem.encode("utf-8")).decode("ascii"),
                },
            },
        ],
        "contexts": [
            {
                "name": context_name,
                "context": {
                    "cluster": cluster_name,
                    "user": user_name,
                },
            },
        ],
        "current-context": context_name,
    }
    return yaml.safe_dump(cfg, sort_keys=False)


def _write_agent_kubeconfig(path: str, content: str) -> None:
    dirpath = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(dirpath, exist_ok=True)
    # Open with 0600 from the start (no window where it's world-readable).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise


# ---------------------------------------------------------------------------
# Scan invocation — import the CLI flow so we stay in-process
# ---------------------------------------------------------------------------

def _run_scan(kubeconfig_path: str) -> dict:
    """Run the existing argus scan pipeline against the scoped kubeconfig
    and return the parsed ``report.json``."""
    # Local import to keep import-time deps for tests minimal.
    from argus import cli

    out_dir = tempfile.mkdtemp(prefix="argus-scan-")
    args = cli.build_parser().parse_args([
        "scan",
        "--kubeconfig", kubeconfig_path,
        "--out", out_dir,
        "--quiet",
    ])
    rc = cli.cmd_scan(args)
    if rc != 0:
        raise RuntimeError(f"scan exited with code {rc}")
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def _cleanup_resources(admin_apis: _AdminApis, state: dict) -> None:
    """Delete the CSR and the ClusterRoleBinding we created. Best-effort:
    log any failure but keep going so we delete as much as we can."""
    from kubernetes.client import exceptions as kexc

    csr_name = state.get("csr_name") or ""
    if state.get("csr_created") and csr_name:
        try:
            admin_apis.certificates_v1.delete_certificate_signing_request(name=csr_name)
        except kexc.ApiException as e:
            if e.status != 404:
                log.warning("cleanup: failed to delete CSR: %s", e)

    if state.get("crb_created"):
        try:
            admin_apis.rbac_v1.delete_cluster_role_binding(
                name=state["cluster_role_binding_name"],
            )
        except kexc.ApiException as e:
            if e.status != 404:
                log.warning("cleanup: failed to delete ClusterRoleBinding: %s", e)


def _best_effort_cleanup(opts: BootstrapOptions, state: dict) -> None:
    """Failure-path cleanup. Loads admin apis fresh because we may have
    failed before we ever loaded them."""
    try:
        admin_apis = _load_admin_apis(opts)
    except Exception:  # noqa: BLE001
        return
    _cleanup_resources(admin_apis, state)


# ---------------------------------------------------------------------------
# Cluster-id resolution
# ---------------------------------------------------------------------------

def _resolve_cluster_id(opts: BootstrapOptions) -> str:
    """Resolution order:
      1. opts.cluster_id_override (set by --cluster-id CLI flag or env)
      2. ARGUS_CLUSTER_ID env var
      3. GET /api/clusters/_self  (preferred — server-side token → cluster lookup)
    """
    if opts.cluster_id_override:
        return opts.cluster_id_override
    env = os.environ.get("ARGUS_CLUSTER_ID")
    if env:
        return env
    return events_client.resolve_cluster_id(opts.control_plane, opts.enroll)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def _short_random(n_bytes: int = 3) -> str:
    """6 hex chars from 3 random bytes."""
    return secrets.token_hex(n_bytes)


def _short_cluster_id(cluster_id: str) -> str:
    """First 8 chars of the cluster id, with non-DNS-safe chars stripped."""
    raw = "".join(ch for ch in cluster_id.lower() if ch.isalnum() or ch == "-")
    return raw[:8] or "unknown"


def _argus_version() -> str:
    try:
        from argus import __version__  # type: ignore[attr-defined]
        return str(__version__)
    except Exception:  # noqa: BLE001
        return "0.0.0"


def _extract_not_after(cert_pem: str) -> Optional[str]:
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        return cert.not_valid_after_utc.isoformat()
    except Exception:  # noqa: BLE001
        try:
            from cryptography import x509  # noqa: F401
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            return cert.not_valid_after.isoformat()
        except Exception:  # noqa: BLE001
            return None


def _print_expiry_warning(not_after: Optional[str]) -> None:
    when = not_after or "<unknown>"
    print(
        f"\nNote: Kubernetes client certificates are NOT revocable. "
        f"This cert expires at {when}. Short TTLs are the only mitigation.",
        file=sys.stderr,
    )
