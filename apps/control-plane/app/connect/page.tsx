import { Placeholder } from '@/components/placeholder';

export default function ConnectPage() {
  return (
    <Placeholder
      title="Connect your cluster"
      description="One copy-paste Helm command installs the read-only agent. It dials out to the relay — no Ingress, no port-forward."
      note="The install-token flow and live “Cluster connected ✓” waiting state are wired in step 1E."
    />
  );
}
