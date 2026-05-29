# Deploying the control-plane (Vercel)

The control-plane is a **standalone Next.js app** (no `workspace:*` deps), so it
deploys on its own — it does not pull in the rest of the monorepo, and it never
touches the in-cluster `api`/`relay`.

It runs in two modes, decided purely by env:

- **Demo mode (no env):** renders the full product against built-in sample data
  (`lib/mock.ts`). Auth is off, the app is open. Perfect for a first deploy /
  click-through of 1C–1F.
- **Live mode:** set Supabase + auth env (below) → real tenant data, SSO, MFA.

## 1. Deploy (demo mode — zero env)

From the app directory, log in once (browser), then deploy:

```bash
cd apps/control-plane
vercel login
vercel --yes          # preview URL
vercel --prod --yes   # production URL
```

That URL is your live sanity-check: Overview, Findings, Attack Paths, Ask,
Report, Fixes, Connect, Permissions — all populated with the demo dataset, with
a working light/dark toggle.

## 2. Turn on live mode (when ready)

### a. Supabase
```bash
supabase login
supabase link --project-ref <your-ref>
supabase db push          # applies migrations 0001 (schema+RLS), 0002 (mfa), 0003 (capabilities)
```

### b. Vercel env (Project → Settings → Environment Variables)
Required:
- `NEXT_PUBLIC_SUPABASE_URL`
- `SUPABASE_SECRET_KEY`  (server-only; the `sb_secret_…` key, or legacy `service_role`)
- `AUTH_SECRET`  (`openssl rand -base64 32`)

At least one SSO provider (callback `https://<your-url>/api/auth/callback/<provider>`):
- `AUTH_GOOGLE_ID` / `AUTH_GOOGLE_SECRET`
- `AUTH_GITHUB_ID` / `AUTH_GITHUB_SECRET`
- `AUTH_MICROSOFT_ENTRA_ID_ID` / `AUTH_MICROSOFT_ENTRA_ID_SECRET`

Local testing shortcut (do **not** set in production): `AUTH_DEV_LOGIN=1` enables
an email-only dev login.

Redeploy after setting env. With `AUTH_SECRET` + a provider present, the app
auto-switches to live mode and enforces sign-in + MFA (approver/admin).

See `.env.example` for the full list.

## 3. Hybrid data-plane (fase 2 — relay + live posture)

This connects a real in-cluster agent to the hosted UI. Three secrets tie the
pieces together; generate each once with `openssl rand -hex 32`:

| secret | set on | purpose |
| --- | --- | --- |
| `RELAY_CONTROL_SECRET` | relay **and** control-plane | hosted app → relay `/command` bridge |
| `RELAY_INGEST_SECRET`  | relay **and** control-plane | relay → control-plane posture webhook |
| CA (`ca.crt`/`ca.key`) | issued locally | per-cluster mTLS agent identity |

### a. Deploy the relay (Fly.io)

The relay holds long-lived WebSocket tunnels, so it runs on Fly (not Vercel).
From the **repo root**:

```bash
fly launch --no-deploy --config apps/relay/fly.toml --dockerfile apps/relay/Dockerfile
fly secrets set -c apps/relay/fly.toml \
  RELAY_CONTROL_SECRET=<s1> \
  RELAY_INGEST_SECRET=<s2> \
  CONTROL_PLANE_URL=https://<your-control-plane> \
  RELAY_CLIENT_CA="$(cat relay-ca/ca.crt)"     # after step (b)
fly deploy --config apps/relay/fly.toml --dockerfile apps/relay/Dockerfile
# sanity: curl https://<relay-host>/healthz  →  {"ok":true,...}
```

### b. mTLS CA (per-cluster agent identity)

```bash
deploy/relay/relay-ca.sh init                 # one-time; keep relay-ca/ca.key OFFLINE
deploy/relay/relay-ca.sh issue <clusterId>    # issues tls.crt/tls.key/ca.crt for one cluster
```

`ca.crt` → the relay's `RELAY_CLIENT_CA`. The per-cluster `tls.crt`/`tls.key`
go into a Secret the agent mounts (the script prints the exact commands).

### c. Control-plane live env (Vercel)

Add to the env from step 2, then redeploy:

- `RELAY_URL` = `wss://<relay-host>`  (shown in the Connect install command)
- `RELAY_HTTP_URL` = `https://<relay-host>`  (the command bridge)
- `RELAY_CONTROL_SECRET` = `<s1>`
- `RELAY_INGEST_SECRET` = `<s2>`

Apply migration `0004` (`supabase db push`) so remediations persist.

### d. Install the agent (hybrid mode)

The Connect screen mints a single-use install token and prints the Helm
command. The chart path comes from `SENTINEL_CHART_REF` (default
`ghcr.io/evanapple83-png/k8s-sentinel`) — the screen verifies a chart is
actually published there before showing the command. With mTLS, also pass the
cert Secret from step (b):

```bash
helm install sentinel oci://$SENTINEL_CHART_REF --version $SENTINEL_CHART_VERSION \
  -n sentinel --create-namespace --set mode=hybrid \
  --set relay.url=wss://<relay-host> \
  --set relay.clientCertSecret=sentinel-relay-cert
```

### e. Verify the loop

1. Connect screen flips to **connected** when the agent registers.
2. Click **Scan now** (or `sentinel scan` in-cluster) → posture streams up the
   tunnel and lands in Supabase via the ingest webhook.
3. Overview / Findings / Attack Paths / Fixes populate with **real** cluster data.
