import { ClusterInventorySchema, type ClusterInventory } from '@k8s-sentinel/core';

/**
 * Offline inventory matching the scanner fixtures: an internet-exposed,
 * privileged, vulnerable `payment-api` in `prod` whose service account can read
 * secrets — the raw material for a real correlated attack path in Phase 2.
 */
export function fixtureInventory(): ClusterInventory {
  return ClusterInventorySchema.parse({
    collectedAt: new Date().toISOString(),
    fromFixture: true,
    namespaces: ['prod', 'kube-system', 'default'],
    workloads: [
      {
        kind: 'Deployment',
        name: 'payment-api',
        namespace: 'prod',
        images: ['payment-api:1.2.0'],
        replicas: 3,
        running: true,
        serviceAccount: 'payment-sa',
        privileged: true,
        runAsRoot: true,
        hostNetwork: false,
        hostPath: false,
        allowPrivilegeEscalation: true,
      },
      {
        kind: 'Deployment',
        name: 'frontend',
        namespace: 'prod',
        images: ['frontend:2.0.0'],
        replicas: 2,
        running: true,
        serviceAccount: 'default',
        privileged: false,
        runAsRoot: false,
      },
      {
        kind: 'Deployment',
        name: 'batch-cleaner',
        namespace: 'default',
        images: ['batch-cleaner:0.4.0'],
        replicas: 0,
        running: false,
        serviceAccount: 'default',
      },
    ],
    services: [
      {
        name: 'payment-api-svc',
        namespace: 'prod',
        type: 'LoadBalancer',
        exposed: true,
        selector: { app: 'payment-api' },
        ports: [443, 8080],
      },
      {
        name: 'frontend-svc',
        namespace: 'prod',
        type: 'ClusterIP',
        exposed: false,
        selector: { app: 'frontend' },
        ports: [80],
      },
    ],
    rbac: [
      {
        serviceAccount: 'payment-sa',
        namespace: 'prod',
        canReadSecrets: true,
        clusterAdmin: true,
        roles: ['cluster-admin'],
      },
      {
        serviceAccount: 'default',
        namespace: 'prod',
        canReadSecrets: false,
        clusterAdmin: false,
        roles: [],
      },
    ],
    networkPolicies: [
      { name: 'kube-system-default-deny', namespace: 'kube-system', appliesTo: {} },
    ],
  });
}
