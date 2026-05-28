"""Stub objects that mirror the attribute shape of the ``kubernetes`` Python
client (snake_case). They let unit tests drive ``argus.inventory.build_inventory``
without installing the kubernetes package or talking to a cluster."""
from __future__ import annotations

from types import SimpleNamespace as N


def _meta(name, namespace=None, labels=None, annotations=None):
    return N(name=name, namespace=namespace,
             labels=labels or {}, annotations=annotations or {})


def _list(items):
    """Shape returned by ``list_*`` calls in the kubernetes client."""
    return N(items=items)


# --- workloads -------------------------------------------------------------

def deployment(
    *,
    name,
    namespace,
    replicas=1,
    ready_replicas=1,
    image="example:latest",
    pod_labels=None,
    service_account_name=None,
    run_as_non_root=None,
    run_as_user=None,
    privileged=False,
    container_run_as_non_root=None,
    container_run_as_user=None,
    node_name=None,
    host_pid=False,
    host_paths=None,           # list[str] of host paths to mount as volumes
    added_capabilities=None,   # list[str] of Linux capabilities added
    volumes=None,
    env=None,
    env_from=None,
):
    caps = N(add=list(added_capabilities or []), drop=[])
    container = N(
        image=image,
        security_context=N(
            run_as_non_root=container_run_as_non_root,
            run_as_user=container_run_as_user,
            privileged=privileged,
            capabilities=caps,
        ),
        env=env or [],
        env_from=env_from or [],
    )
    all_volumes = list(volumes or [])
    for hp in (host_paths or []):
        all_volumes.append(N(host_path=N(path=hp), secret=None, projected=None))
    pod_spec = N(
        containers=[container],
        volumes=all_volumes,
        service_account_name=service_account_name,
        node_name=node_name,
        node_selector={},
        host_pid=host_pid,
        security_context=N(run_as_non_root=run_as_non_root, run_as_user=run_as_user),
    )
    template = N(metadata=_meta(name=None, labels=pod_labels or {}), spec=pod_spec)
    return N(
        metadata=_meta(name, namespace),
        spec=N(replicas=replicas, template=template),
        status=N(ready_replicas=ready_replicas),
    )


def daemonset(*, name, namespace, desired=1, available=1, pod_labels=None,
              image="example:latest", service_account_name=None, node_name=None):
    container = N(
        image=image,
        security_context=N(privileged=False, capabilities=N(add=[], drop=[])),
        env=[], env_from=[],
    )
    pod_spec = N(
        containers=[container], volumes=[],
        service_account_name=service_account_name,
        node_name=node_name, node_selector={}, host_pid=False,
        security_context=N(run_as_non_root=None, run_as_user=None),
    )
    template = N(metadata=_meta(name=None, labels=pod_labels or {}), spec=pod_spec)
    return N(
        metadata=_meta(name, namespace),
        spec=N(replicas=None, template=template),
        status=N(desired_number_scheduled=desired, number_available=available),
    )


# --- services / ingress / netpol -------------------------------------------

def service(*, name, namespace, selector, type_="ClusterIP"):
    return N(metadata=_meta(name, namespace), spec=N(selector=selector, type=type_))


def ingress(*, name, namespace, host, backend_service):
    backend = N(service=N(name=backend_service))
    path = N(backend=backend)
    rule = N(host=host, http=N(paths=[path]))
    return N(metadata=_meta(name, namespace), spec=N(rules=[rule]))


def network_policy(*, name, namespace, match_labels, policy_types=("Ingress",),
                   ingress=None, allow_external_cidr=None):
    """``ingress`` parameter shapes:
      * ``None`` / ``[]``       → empty (deny all inbound)
      * truthy list of rules   → custom; pass ``allow_external_cidr="0.0.0.0/0"``
                                 to inject an ipBlock rule (engine treats as open)
    """
    rules = list(ingress or [])
    if allow_external_cidr is not None and not rules:
        rules = [N(_from=[N(ip_block=N(cidr=allow_external_cidr))])]
    return N(
        metadata=_meta(name, namespace),
        spec=N(
            pod_selector=N(match_labels=dict(match_labels)),
            policy_types=list(policy_types),
            ingress=rules or None,
        ),
    )


# --- nodes ------------------------------------------------------------------

def node(name):
    return N(metadata=_meta(name))


# --- secret references inside workloads ------------------------------------

def secret_volume(secret_name):
    return N(secret=N(secret_name=secret_name), projected=None, host_path=None)


def env_from_secret(secret_name):
    return N(secret_ref=N(name=secret_name), config_map_ref=None)


def env_from_secret_key(secret_name, key="x"):
    return N(name="X", value=None, value_from=N(secret_key_ref=N(name=secret_name, key=key)))


# --- RBAC ------------------------------------------------------------------

def rule(verbs, resources):
    return N(verbs=list(verbs), resources=list(resources))


def role(*, name, namespace, rules):
    return N(metadata=_meta(name, namespace), rules=list(rules))


def cluster_role(*, name, rules):
    return N(metadata=_meta(name, None), rules=list(rules))


def subject_sa(name, namespace):
    return N(kind="ServiceAccount", name=name, namespace=namespace)


def role_binding(*, name, namespace, role_name, subjects, role_kind="Role"):
    return N(
        metadata=_meta(name, namespace),
        role_ref=N(kind=role_kind, name=role_name),
        subjects=list(subjects),
    )


def cluster_role_binding(*, name, role_name, subjects):
    return N(
        metadata=_meta(name, None),
        role_ref=N(kind="ClusterRole", name=role_name),
        subjects=list(subjects),
    )


def service_account(*, name, namespace, cloud_identity=None):
    """A ServiceAccount object. ``cloud_identity`` injects the appropriate
    annotation so the collector picks it up."""
    annotations = {}
    if cloud_identity:
        annotations["eks.amazonaws.com/role-arn"] = cloud_identity
    return N(metadata=_meta(name, namespace, annotations=annotations))


# --- Apis bundle ------------------------------------------------------------

class FakeApis:
    """Drop-in for argus.inventory.Apis. Each ``list_*`` call returns the
    pre-configured object list wrapped in the kubernetes-style ``.items`` shape."""

    def __init__(self, *, namespaces=(), deployments=(), statefulsets=(), daemonsets=(),
                 services=(), ingresses=(), netpols=(), nodes=(), service_accounts=(),
                 roles=(), cluster_roles=(), role_bindings=(), cluster_role_bindings=()):
        self._namespaces = [N(metadata=_meta(n)) for n in namespaces]
        self._deployments = list(deployments)
        self._statefulsets = list(statefulsets)
        self._daemonsets = list(daemonsets)
        self._services = list(services)
        self._ingresses = list(ingresses)
        self._netpols = list(netpols)
        self._nodes = [node(n) if isinstance(n, str) else n for n in nodes]
        self._service_accounts = list(service_accounts)
        self._roles = list(roles)
        self._cluster_roles = list(cluster_roles)
        self._role_bindings = list(role_bindings)
        self._cluster_role_bindings = list(cluster_role_bindings)

        outer = self

        class _AppsV1:
            def list_deployment_for_all_namespaces(self): return _list(outer._deployments)
            def list_stateful_set_for_all_namespaces(self): return _list(outer._statefulsets)
            def list_daemon_set_for_all_namespaces(self): return _list(outer._daemonsets)

        class _CoreV1:
            def list_namespace(self): return _list(outer._namespaces)
            def list_service_for_all_namespaces(self): return _list(outer._services)
            def list_node(self): return _list(outer._nodes)
            def list_service_account_for_all_namespaces(self):
                return _list(outer._service_accounts)
            # Secret listing is intentionally NOT implemented — the collector
            # must derive secret reachability from workload references alone
            # so the deployed RBAC can stay free of get/list on secrets.

        class _NetV1:
            def list_ingress_for_all_namespaces(self): return _list(outer._ingresses)
            def list_network_policy_for_all_namespaces(self): return _list(outer._netpols)

        class _RbacV1:
            def list_role_for_all_namespaces(self): return _list(outer._roles)
            def list_cluster_role(self): return _list(outer._cluster_roles)
            def list_role_binding_for_all_namespaces(self): return _list(outer._role_bindings)
            def list_cluster_role_binding(self): return _list(outer._cluster_role_bindings)

        self.apps_v1 = _AppsV1()
        self.core_v1 = _CoreV1()
        self.networking_v1 = _NetV1()
        self.rbac_v1 = _RbacV1()
