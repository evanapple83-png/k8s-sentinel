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

See `.env.example` for the full list. The relay URL (`RELAY_URL`) is wired in
fase 2; until then the Connect screen shows the install command with a
placeholder relay host.
