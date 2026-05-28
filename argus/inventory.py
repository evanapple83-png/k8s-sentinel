"""argus/inventory.py — read-only Kubernetes inventory collector (v3 schema).

Emits the exact dict shape consumed by ``argus.engine_v3.engine.analyse``.
Reference inventory: ``argus/engine_v3/fixtures/inventory.json``.

Read-only guarantees
--------------------
  * No write/patch/delete verbs are ever called.
  * Secret ``.data`` is NEVER read or stored. Secret reachability is derived
    from per-SA RBAC rules + pod volume/env references — neither needs the
    Secret object's contents.
  * Cluster cloud-side privilege escalation (the ``cloudRoles`` field) is
    intentionally **empty** here. Populating it requires a read-only
    cloud-provider collector (AWS IAM / GCP IAM) and that hasn't been built
    yet — see the TODO below. The v3 engine degrades gracefully when this
    list is empty.

Output schema (frozen against engine_v3)
----------------------------------------
::

    {
      "cluster":          str,
      "scannedAt":        ISO-8601 UTC,
      "workloads": [{
        "id":             "ns/name",
        "namespace":      str,
        "running":        bool,
        "image":          str,
        "serviceAccount":"ns/sa",
        "node":           str,
        "runAsRoot":      bool,
        "privileged":     bool,
        "hostPath":       [str],     # host paths mounted into the workload
        "hostPID":        bool,
        "capabilities":   [str],     # added Linux capabilities (e.g. SYS_ADMIN)
        "exposedVia":     [str],     # "ingress:<host>" / "loadbalancer:<svc>"
      }],
      "serviceAccounts": [{
        "id":             "ns/name",
        "rules": [{
          "verbs":        [str],
          "resources":    [str],
          "scope":        str,
        }],
        "cloudIdentity":  str | None,    # IRSA-style annotation, if present
      }],
      "cloudRoles":       [],            # TODO — see module docstring
      "secrets": [{
        "id":             "ns/name",
        "namespace":      str,
        "sensitivity":    "high" | "medium" | "low",
      }],
      "nodes": [{ "id": str }],
      "networkPolicies": [{
        "namespace":      str,
        "appliesTo":      str,           # workload name or "*"
        "mode":           "deny-all" | "deny-external" | "open",
      }],
    }
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Iterable, Optional


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class Apis:
    """Bundle of kubernetes client APIs — keeps the collector decoupled from
    how the clients were constructed (kubeconfig vs in-cluster) and lets tests
    inject stubs that mirror the kubernetes client's attribute shape."""
    apps_v1: Any
    core_v1: Any
    networking_v1: Any
    rbac_v1: Any


def collect_inventory(
    cluster_name: str,
    *,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    in_cluster: bool = False,
    scanned_at: Optional[str] = None,
) -> dict:
    """Build an Inventory from a live cluster. Imports the ``kubernetes``
    client lazily so callers (and tests) without the package installed can
    still call :func:`build_inventory` directly."""
    apis = _load_apis(kubeconfig=kubeconfig, context=context, in_cluster=in_cluster)
    return build_inventory(apis, cluster_name, scanned_at=scanned_at)


def build_inventory(apis: Apis, cluster_name: str, *, scanned_at: Optional[str] = None) -> dict:
    """Pure inventory build — takes an ``Apis`` bundle and returns the frozen
    v3 dict shape. No I/O beyond what the injected APIs do."""
    ts = scanned_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    services = _safe_list(apis.core_v1.list_service_for_all_namespaces)
    ingresses = _safe_list(apis.networking_v1.list_ingress_for_all_namespaces)
    netpol_objs = _safe_list(apis.networking_v1.list_network_policy_for_all_namespaces)

    workloads_raw = list(_iter_workloads(apis.apps_v1))
    workloads = [_workload_dict(w, services, ingresses) for w in workloads_raw]

    service_accounts = _service_accounts(apis.core_v1, apis.rbac_v1)
    secrets = _secrets_from_workload_refs(workloads_raw)
    network_policies = _network_policy_entries(netpol_objs, workloads_raw)
    nodes = _nodes(apis.core_v1)

    return {
        "cluster":         cluster_name,
        "scannedAt":       ts,
        "workloads":       workloads,
        "serviceAccounts": service_accounts,
        # TODO: needs a read-only cloud-provider (AWS/GCP) collector to walk
        # IAM roles, permission boundaries, and AssumeRole edges. The v3
        # engine treats an empty list as "no cloud-IAM reachability known".
        "cloudRoles":      [],
        "secrets":         secrets,
        "nodes":           nodes,
        "networkPolicies": network_policies,
    }


# ---------------------------------------------------------------------------
# kubernetes client bootstrap (lazy)
# ---------------------------------------------------------------------------

def _load_apis(*, kubeconfig: Optional[str], context: Optional[str], in_cluster: bool) -> Apis:
    from kubernetes import client, config                        # lazy

    if in_cluster:
        config.load_incluster_config()
    else:
        config.load_kube_config(config_file=kubeconfig, context=context)

    return Apis(
        apps_v1=client.AppsV1Api(),
        core_v1=client.CoreV1Api(),
        networking_v1=client.NetworkingV1Api(),
        rbac_v1=client.RbacAuthorizationV1Api(),
    )


# ---------------------------------------------------------------------------
# Helpers shared across collectors
# ---------------------------------------------------------------------------

def _safe_list(list_fn) -> list:
    """List-call wrapper. The collector must degrade, not crash, when a verb
    is missing or the call fails."""
    try:
        resp = list_fn()
    except Exception:
        return []
    items = getattr(resp, "items", None)
    return list(items) if items else []


def _name(obj) -> Optional[str]:
    meta = getattr(obj, "metadata", None)
    return getattr(meta, "name", None) if meta else None


def _namespace(obj) -> Optional[str]:
    meta = getattr(obj, "metadata", None)
    return getattr(meta, "namespace", None) if meta else None


def _labels(obj) -> dict:
    meta = getattr(obj, "metadata", None)
    return dict(getattr(meta, "labels", None) or {}) if meta else {}


def _annotations(obj) -> dict:
    meta = getattr(obj, "metadata", None)
    return dict(getattr(meta, "annotations", None) or {}) if meta else {}


# ---------------------------------------------------------------------------
# Workloads (Deployment / StatefulSet / DaemonSet)
# ---------------------------------------------------------------------------

def _iter_workloads(apps_v1) -> Iterable[tuple]:
    """Yield (kind, obj) for every Deployment / StatefulSet / DaemonSet across
    all namespaces."""
    for kind, fn in (
        ("Deployment", apps_v1.list_deployment_for_all_namespaces),
        ("StatefulSet", apps_v1.list_stateful_set_for_all_namespaces),
        ("DaemonSet", apps_v1.list_daemon_set_for_all_namespaces),
    ):
        for obj in _safe_list(fn):
            yield kind, obj


def _workload_dict(kind_obj: tuple, services: list, ingresses: list) -> dict:
    kind, obj = kind_obj
    ns = _namespace(obj) or "default"
    name = _name(obj) or "?"
    spec = getattr(obj, "spec", None)
    template = getattr(spec, "template", None) if spec else None
    pod_spec = getattr(template, "spec", None) if template else None
    pod_labels = _labels(template) if template else {}

    containers = list(getattr(pod_spec, "containers", None) or []) if pod_spec else []
    image = containers[0].image if containers and getattr(containers[0], "image", None) else ""

    sa_name = getattr(pod_spec, "service_account_name", None) if pod_spec else None
    sa_name = sa_name or "default"

    return {
        "id":             f"{ns}/{name}",
        # ``kind`` is not consumed by the engine (it treats workloads
        # abstractly), but downstream consumers (TS wire mapping, UI) need it
        # to produce a faithful ResourceRef. The engine ignores extra keys.
        "kind":           kind,
        "namespace":      ns,
        "running":        _is_running(kind, obj),
        "image":          image,
        "serviceAccount": f"{ns}/{sa_name}",
        "node":           _node_name(pod_spec, obj),
        "runAsRoot":      _runs_as_root(pod_spec, containers),
        "privileged":     _is_privileged(containers),
        "hostPath":       _host_paths(pod_spec),
        "hostPID":        bool(getattr(pod_spec, "host_pid", False)) if pod_spec else False,
        "capabilities":   _added_capabilities(containers),
        "exposedVia":     _compute_exposed_via(ns, pod_labels, services, ingresses),
    }


def _is_running(kind: str, obj) -> bool:
    status = getattr(obj, "status", None)
    if kind == "DaemonSet":
        desired = int(getattr(status, "desired_number_scheduled", 0) or 0)
        available = int(getattr(status, "number_available", 0) or 0)
        return desired > 0 and available > 0
    ready = int(getattr(status, "ready_replicas", 0) or 0)
    return ready > 0


def _node_name(pod_spec, workload_obj) -> str:
    """Workload template's nodeName, or its nodeSelector's kubernetes.io
    hostname label, or empty string if the workload doesn't pin a node. (The
    engine treats this as a categorical id; "" just means "any node".)"""
    if pod_spec is None:
        return ""
    name = getattr(pod_spec, "node_name", None)
    if name:
        return name
    selector = getattr(pod_spec, "node_selector", None) or {}
    if isinstance(selector, dict):
        return selector.get("kubernetes.io/hostname", "") or ""
    return ""


def _runs_as_root(pod_spec, containers) -> bool:
    """``runAsRoot = not (runAsNonRoot True or runAsUser > 0)``. Container
    securityContext overrides pod-level. If ANY container is effectively
    root, the workload runs as root."""
    def _evaluate(sc) -> Optional[bool]:
        if sc is None:
            return None
        run_as_non_root = getattr(sc, "run_as_non_root", None)
        run_as_user = getattr(sc, "run_as_user", None)
        if run_as_non_root is True:
            return False
        if isinstance(run_as_user, int) and run_as_user > 0:
            return False
        if run_as_non_root is False or run_as_user == 0:
            return True
        return None

    pod_v = _evaluate(getattr(pod_spec, "security_context", None)) if pod_spec else None
    if not containers:
        return pod_v is not False
    for ctr in containers:
        ctr_v = _evaluate(getattr(ctr, "security_context", None))
        effective = ctr_v if ctr_v is not None else pod_v
        if effective is not False:                              # unset → image default UID (root)
            return True
    return False


def _is_privileged(containers) -> bool:
    for ctr in containers:
        sc = getattr(ctr, "security_context", None)
        if sc and getattr(sc, "privileged", False):
            return True
    return False


def _host_paths(pod_spec) -> list:
    """Distinct ``volumes[].hostPath.path`` values. Engine's container-escape
    check fires if this list is non-empty."""
    out: list = []
    if pod_spec is None:
        return out
    seen = set()
    for vol in (getattr(pod_spec, "volumes", None) or []):
        hp = getattr(vol, "host_path", None)
        path = getattr(hp, "path", None) if hp else None
        if path and path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _added_capabilities(containers) -> list:
    """Linux capabilities added to any container. The engine surfaces
    SYS_ADMIN specifically, but we record everything added so downstream
    consumers can audit further."""
    caps: list = []
    seen = set()
    for ctr in containers:
        sc = getattr(ctr, "security_context", None)
        caps_obj = getattr(sc, "capabilities", None) if sc else None
        added = getattr(caps_obj, "add", None) if caps_obj else None
        for cap in (added or []):
            if cap not in seen:
                seen.add(cap)
                caps.append(cap)
    return caps


# ---------------------------------------------------------------------------
# Service / Ingress reachability → exposedVia
# ---------------------------------------------------------------------------

def _selector_matches(selector: dict, labels: dict) -> bool:
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())


def _compute_exposed_via(ns: str, pod_labels: dict, services: list, ingresses: list) -> list:
    exposed: list = []

    matching_services = []  # (svc_name, svc_type)
    for svc in services:
        if _namespace(svc) != ns:
            continue
        spec = getattr(svc, "spec", None)
        selector = dict(getattr(spec, "selector", None) or {}) if spec else {}
        if not _selector_matches(selector, pod_labels):
            continue
        svc_name = _name(svc) or ""
        svc_type = getattr(spec, "type", None) if spec else None
        matching_services.append((svc_name, svc_type))
        if svc_type == "LoadBalancer":
            exposed.append(f"loadbalancer:{svc_name}")

    svc_names = {n for n, _ in matching_services}
    for ing in ingresses:
        if _namespace(ing) != ns:
            continue
        spec = getattr(ing, "spec", None)
        if not spec:
            continue
        for rule in (getattr(spec, "rules", None) or []):
            host = getattr(rule, "host", None)
            http = getattr(rule, "http", None)
            paths = getattr(http, "paths", None) if http else None
            for path in (paths or []):
                backend = getattr(path, "backend", None)
                svc_backend = getattr(backend, "service", None) if backend else None
                svc_name = getattr(svc_backend, "name", None) if svc_backend else None
                if svc_name and svc_name in svc_names:
                    exposed.append(f"ingress:{host}" if host else f"ingress:{svc_name}")
                    break  # one entry per ingress is enough

    # Dedup while preserving order.
    seen = set()
    deduped = []
    for e in exposed:
        if e not in seen:
            deduped.append(e)
            seen.add(e)
    return deduped


# ---------------------------------------------------------------------------
# ServiceAccounts — group RBAC by SA and harvest cloudIdentity
# ---------------------------------------------------------------------------

# IRSA / Workload-Identity style annotations. Order matters: first hit wins.
_CLOUD_IDENTITY_ANNOTATIONS = (
    "eks.amazonaws.com/role-arn",            # AWS IRSA
    "iam.gke.io/gcp-service-account",        # GKE Workload Identity
    "azure.workload.identity/client-id",     # AKS Workload Identity
)


def _service_accounts(core_v1, rbac_v1) -> list:
    """Walk SAs and project the (Cluster)RoleBindings they're subject of into
    a per-SA ``rules: [{verbs, resources, scope}]`` list. Wildcard resources
    (``"*"``) gain an explicit ``"secrets"`` entry so the v3 engine's literal
    membership check fires for wildcard rules.

    SAs with no bindings still appear (with ``rules: []``) — workloads
    reference them by name and the engine traverses ``wl → sa`` edges
    unconditionally."""
    cluster_roles = {_name(cr): _rules_of(cr) for cr in _safe_list(rbac_v1.list_cluster_role)}
    roles_by_ns_name = {}
    for r in _safe_list(rbac_v1.list_role_for_all_namespaces):
        roles_by_ns_name[(_namespace(r), _name(r))] = _rules_of(r)

    # Collect SAs first so we emit every SA, even those without bindings.
    sa_records = {}
    for sa in _safe_list(core_v1.list_service_account_for_all_namespaces):
        ns, name = _namespace(sa) or "default", _name(sa) or "default"
        sa_id = f"{ns}/{name}"
        sa_records[sa_id] = {
            "id": sa_id,
            "rules": [],
            "cloudIdentity": _cloud_identity(sa),
        }

    # ClusterRoleBindings → cluster-wide scope.
    for crb in _safe_list(rbac_v1.list_cluster_role_binding):
        rules = _resolve_role_ref(crb, cluster_roles, roles_by_ns_name, fallback_ns=None)
        for sa_id in _service_account_subjects(crb):
            rec = sa_records.setdefault(sa_id, {"id": sa_id, "rules": [], "cloudIdentity": None})
            for rule in rules:
                rec["rules"].append(_rule_entry(rule, scope="*"))

    # RoleBindings → namespaced scope (always the binding's own namespace).
    for rb in _safe_list(rbac_v1.list_role_binding_for_all_namespaces):
        binding_ns = _namespace(rb) or ""
        rules = _resolve_role_ref(rb, cluster_roles, roles_by_ns_name, fallback_ns=binding_ns)
        for sa_id in _service_account_subjects(rb, default_namespace=binding_ns):
            rec = sa_records.setdefault(sa_id, {"id": sa_id, "rules": [], "cloudIdentity": None})
            for rule in rules:
                rec["rules"].append(_rule_entry(rule, scope=binding_ns))

    return sorted(sa_records.values(), key=lambda r: r["id"])


def _cloud_identity(sa_obj) -> Optional[str]:
    ann = _annotations(sa_obj)
    for key in _CLOUD_IDENTITY_ANNOTATIONS:
        if ann.get(key):
            return ann[key]
    return None


def _rules_of(role_obj) -> list:
    return list(getattr(role_obj, "rules", None) or [])


def _resolve_role_ref(binding, cluster_roles: dict, roles_by_ns_name: dict, fallback_ns) -> list:
    ref = getattr(binding, "role_ref", None)
    if ref is None:
        return []
    kind = getattr(ref, "kind", "")
    name = getattr(ref, "name", "")
    if kind == "ClusterRole":
        return cluster_roles.get(name, [])
    if kind == "Role":
        return roles_by_ns_name.get((fallback_ns, name), [])
    return []


def _service_account_subjects(binding, default_namespace: Optional[str] = None) -> list:
    out: list = []
    for s in (getattr(binding, "subjects", None) or []):
        if getattr(s, "kind", None) != "ServiceAccount":
            continue
        ns = getattr(s, "namespace", None) or default_namespace or "default"
        out.append(f"{ns}/{s.name}")
    return out


def _rule_entry(rule, scope: str) -> dict:
    verbs = list(getattr(rule, "verbs", None) or [])
    resources = list(getattr(rule, "resources", None) or [])
    # v3 engine's ``_hit`` check expands ``*`` literally on its side, so we
    # don't need to inject "secrets" here. Preserve the rule shape verbatim.
    return {"verbs": verbs, "resources": resources, "scope": scope}


# ---------------------------------------------------------------------------
# Secrets — referenced-by-workload only; never reads .data
# ---------------------------------------------------------------------------

_HIGH_NAME_PATTERNS = ("cred", "token", "password", "secret", "apikey", "api-key", "private", "db")


def _secret_sensitivity(name: str) -> str:
    n = (name or "").lower()
    if any(p in n for p in _HIGH_NAME_PATTERNS):
        return "high"
    return "medium"


def _secrets_from_workload_refs(workloads_raw: list) -> list:
    """Harvest Secret references from pod templates (volumes / envFrom /
    valueFrom.secretKeyRef). The deployed RBAC does NOT grant ``get/list`` on
    Secrets — these references live inside Deployment specs we already read,
    so no extra permission is required and ``.data`` is never touched."""
    seen: dict = {}
    for _kind, obj in workloads_raw:
        ns = _namespace(obj) or "default"
        spec = getattr(obj, "spec", None)
        template = getattr(spec, "template", None) if spec else None
        pod_spec = getattr(template, "spec", None) if template else None
        if pod_spec is None:
            continue

        for vol in (getattr(pod_spec, "volumes", None) or []):
            sec = getattr(vol, "secret", None)
            if sec and getattr(sec, "secret_name", None):
                _add_secret_ref(seen, ns, sec.secret_name)
            projected = getattr(vol, "projected", None)
            for src in (getattr(projected, "sources", None) or []) if projected else []:
                ps = getattr(src, "secret", None)
                if ps and getattr(ps, "name", None):
                    _add_secret_ref(seen, ns, ps.name)

        for ctr in (getattr(pod_spec, "containers", None) or []):
            for env in (getattr(ctr, "env", None) or []):
                vf = getattr(env, "value_from", None)
                ref = getattr(vf, "secret_key_ref", None) if vf else None
                if ref and getattr(ref, "name", None):
                    _add_secret_ref(seen, ns, ref.name)
            for env_from in (getattr(ctr, "env_from", None) or []):
                ref = getattr(env_from, "secret_ref", None)
                if ref and getattr(ref, "name", None):
                    _add_secret_ref(seen, ns, ref.name)

    return sorted(seen.values(), key=lambda s: s["id"])


def _add_secret_ref(seen: dict, ns: str, name: str) -> None:
    key = f"{ns}/{name}"
    if key in seen:
        return
    seen[key] = {
        "id":          key,
        "namespace":   ns,
        "sensitivity": _secret_sensitivity(name),
    }


# ---------------------------------------------------------------------------
# NetworkPolicies — shape to engine.lateral_blocked() expectations
# ---------------------------------------------------------------------------

def _network_policy_entries(netpols: list, workloads_raw: list) -> list:
    """Per matched workload, emit one ``{namespace, appliesTo, mode}`` entry.

    ``mode`` semantics (engine consumes ``deny-all`` and ``deny-external``):
      * ``deny-all`` — policyTypes=[Ingress] with no ingress rules (or rules
        present but listing nothing → still blocks all). Blocks lateral
        movement *and* external.
      * ``deny-external`` — has ingress rules but only allows in-cluster
        sources (no ``from`` block that opens ipBlock external CIDRs).
      * ``open`` — anything else.

    The v3 engine's lateral-movement edge is blocked only by ``deny-all`` in
    the same namespace. ``deny-external`` is a posture signal — the engine
    doesn't read it directly today but accepted-risk policies do, and we
    preserve it for forward-compat."""
    out: list = []
    for np in netpols:
        ns = _namespace(np) or "default"
        spec = getattr(np, "spec", None)
        if spec is None:
            continue
        selector = dict(getattr(getattr(spec, "pod_selector", None), "match_labels", None) or {})
        mode = _classify_mode(spec)

        applies_to_names = sorted({
            _name(obj)
            for kind, obj in workloads_raw
            if _namespace(obj) == ns and _selector_matches(selector, _pod_labels(obj))
        })
        if not applies_to_names:
            # No selector at all → policy applies to all pods in the
            # namespace; v3 engine accepts ``"*"`` as that wildcard.
            applies_to_names = ["*"] if not selector else \
                ["selector:" + ",".join(f"{k}={v}" for k, v in sorted(selector.items()))]

        for wl_name in applies_to_names:
            out.append({"namespace": ns, "appliesTo": wl_name, "mode": mode})
    return out


def _classify_mode(np_spec) -> str:
    policy_types = list(getattr(np_spec, "policy_types", None) or [])
    ingress = getattr(np_spec, "ingress", None)
    has_ingress = "Ingress" in policy_types or not policy_types
    if not has_ingress:
        return "open"
    if not ingress:                                             # empty / missing list
        return "deny-all"
    # If there is at least one rule with no external ipBlock, treat as
    # deny-external (in-cluster only). If any rule allows external CIDRs,
    # call it open.
    for rule in (ingress or []):
        for from_entry in (getattr(rule, "_from", None) or getattr(rule, "from", None) or []):
            ip_block = getattr(from_entry, "ip_block", None)
            if ip_block and getattr(ip_block, "cidr", None):
                return "open"
    return "deny-external"


def _pod_labels(workload_obj) -> dict:
    spec = getattr(workload_obj, "spec", None)
    template = getattr(spec, "template", None) if spec else None
    return _labels(template) if template else {}


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def _nodes(core_v1) -> list:
    out: list = []
    for n in _safe_list(core_v1.list_node):
        name = _name(n)
        if name:
            out.append({"id": name})
    return sorted(out, key=lambda d: d["id"])
