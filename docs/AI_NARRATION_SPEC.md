# K8s Sentinel — AI narration layer (build spec)

> Adds the CVP-unlocked model-narration features on top of the deterministic v3
> engine: **Ask** (chat over cluster posture), **finding explanations**, **attack-path
> narration**, and **"Why this fix?"** reasoning on choke points.
>
> **The engine stays the source of truth.** The model never replaces correlation or
> scoring; it explains and converses over the report the engine already produced.
>
> **Feature-flag everything; do NOT merge to main or deploy.**

## 0. Why this is now possible

CVP approval (Anthropic) is in place for our org. Dual-use defensive reasoning is
permitted for this organization, so the model can narrate attack paths, explain
exploitability, and reason about remediations in plain language. The CVP approval is
**per-org and use-case-bounded** — keep the model in the defensive lane (no exploit
code, no payloads, no offensive tooling) so we stay aligned with what was approved.

## 1. Architecture (non-negotiable)

- **API keys stay server-side.** The dashboard never sees an Anthropic key. The
  dashboard calls our `apps/api`; our backend calls Anthropic with the verified-org key.
- **Source of truth = the latest `report.json` for the active cluster.** The model
  receives that as context, plus the specific target (finding id, path index, choke-point
  index, or chat question). It does not get the entire DB or other clusters' data.
- **Model:** `claude-sonnet-4-6` by default (good quality, sensible cost). Make it
  configurable per endpoint.
- **Streaming** for chat (Ask); single-shot is fine for the explanation endpoints.
- **Audit-log every model call** (workspace, user, cluster, scan id, endpoint, prompt
  hash, output, timestamp). This supports the CVP "ongoing monitoring" obligation.
- **Per-workspace rate limit and monthly cost cap** from day one — Anthropic costs add
  up; surprise bills are not a feature.

## 2. The defensive system prompt (shared by all endpoints)

Use this as the system prompt for every AI endpoint, with minor task-specific framing:

> You are the security analyst inside K8s Sentinel. You explain Kubernetes posture
> findings to a smart non-expert.
>
> The provided cluster scan report (JSON) is your sole source of truth. Only cite
> findings, paths, choke points, and assets that appear in it; reference findings by ID
> (e.g., `F-001`), paths by their target, and choke points by their fix description. If
> the report does not contain enough to answer, say so — do not invent.
>
> You may explain exploitability, reachability, and attack-path reasoning in defensive
> language. You may NOT generate exploit code, payloads, offensive tooling, or step-by-step
> attack instructions. You may NOT propose commands that modify the cluster — remediations
> are described conceptually (patch X, drop privileged on Y, remove RBAC verb Z) and
> handed to the user, never executed.
>
> Be concise. Use SSVC vocabulary (Act / Attend / Track / Track\*) where it helps. When
> something is uncertain (e.g., reachability inferred from an absent NetworkPolicy), say
> so explicitly.

## 3. Report context the model receives

The v3 engine writes `report.json` with this shape — pass the latest one for the active
cluster verbatim as context, plus the specific target the user clicked on:

`{ cluster, intel:{source,version,kev_count}, riskScore, reachableJewels[], paths:{target:[[from,to,label,control,inferred],...]}, chokePoints:[{control,breaks,targets[]}], findings:[{id,cve,title,target,kev,ransomware,epss,cvss,exposure,confidence,decision,score,reaches[]}] }`

For large reports, trim to the relevant slice (the targeted finding/path/fix plus the
top-level fields). For Ask, pass the full report (or the top N findings + all paths +
choke points + intel — whichever keeps within a sane context budget).

## 4. Backend endpoints (apps/api / control-plane)

All four return JSON `{ explanation: string, citations: [{type, id|index}] }` for
non-streaming, and SSE/streamed text + a final citations event for `ask`.

- **`POST /api/ai/explain-finding`** — body: `{ clusterId, findingId }`. "What is this
  finding, why does it matter on *this* workload, what's the recommended action?"
- **`POST /api/ai/explain-path`** — body: `{ clusterId, pathTarget }`. Narrate the
  attack path from external entry to the crown jewel in defensive terms; call out
  inferred (low-confidence) edges; explain which choke points break it.
- **`POST /api/ai/explain-fix`** — body: `{ clusterId, chokePointIndex }`. Why this fix
  is the highest-leverage move, what it changes in the graph (paths broken), and
  practical notes (e.g., side effects of dropping a workload's privileged flag).
- **`POST /api/ai/ask`** (streaming) — body: `{ clusterId, question, conversationId? }`.
  Free-form Q&A scoped to the active cluster's latest scan. Persist conversation history
  per `conversationId` (capped length); reset on cluster change.

Each endpoint:

1. Loads the latest scan for `clusterId` (404 if none).
2. Builds the prompt: system prompt (§2) + report context (§3) + user message describing
   the target/question.
3. Calls the Anthropic API server-side with the verified-org key.
4. Streams or returns the response; writes an audit log row.
5. Enforces rate limit (e.g., 30/min per user, 500/day per workspace, configurable) and
   the monthly cost cap; returns a clean 429 with reset time on limit.

## 5. Frontend (apps/dashboard)

Use existing design system; gate the whole layer behind a feature flag
(`ff.aiNarration`).

- **Findings table** — each row gets an **Explain** button (or icon) opening a side
  panel with the model's explanation. Show a citation footer (e.g., "Based on F-001
  and path → CLUSTER-ADMIN").
- **Attack Paths page** — under each path's deterministic chain, an auto-loaded
  **Narration** paragraph (lazy-load on view). Mark inferred edges as such in the
  paragraph.
- **Choke points / "Do this first" card** on Overview — each fix has a **Why this fix?**
  expander that loads the explanation.
- **Ask** sidebar item — a streaming chat scoped to the active cluster. Show the active
  scan timestamp at the top ("answering from scan at 2026-05-28 09:14"). Reset
  conversation on cluster change. Show citations inline as `F-001` badges that scroll to
  the finding when clicked.

## 6. Security, cost, and compliance

- **API key server-side only.** Never expose it to the dashboard, never log it.
- **Calls use the CVP-verified org credentials.** Document this in the deploy notes (org
  ID is on file with Anthropic). If we ever spin up a second org, it needs its own CVP
  application — these endpoints should refuse to use a non-verified org's key.
- **Rate limit + monthly cost cap per workspace** — emit a banner in the UI when 80%
  consumed; hard block at 100% (clean 429 with a "raise the cap" link).
- **Audit log** — append-only, retained for at least 90 days. Include workspace, user,
  cluster, scan id, endpoint, prompt hash, model id, response token count, timestamp.
  This is what we'd show Anthropic if the CVP use-case fit ever needs to be reviewed.
- **The model gives explanations only.** No "take this action for me" affordances. All
  remediations are descriptive; humans run them.

## 7. Hallucination guardrails

- The system prompt (§2) constrains the model to the report's IDs and assets and
  requires it to say "not in the current scan" when something isn't there.
- Post-process: parse the response for finding IDs / path targets and verify they exist
  in the report. If a referenced ID isn't in the report, append a soft warning footer:
  "Note: this response referenced an item not in the current scan."
- Cache explanations per `(clusterId, scanId, target)` so the same finding gives a stable
  answer until the next scan, and to control cost.

## 8. Build order — stop for review after each

1. `/api/ai/explain-finding` end to end (server-side key, system prompt, audit log, basic
   rate limit). Verify on a fixture report.
2. Frontend **Findings → Explain** wired to it.
3. `/api/ai/explain-path` + **Attack Paths narration** UI.
4. `/api/ai/explain-fix` + **Why this fix?** expanders on the Overview choke points.
5. `/api/ai/ask` streaming + **Ask** sidebar chat (conversation state, citations).
6. Cost cap UI + audit-log viewer (admin-only) + hallucination post-check.

## 9. Definition of done

- Findings, attack paths, and choke points each surface a grounded, defensive
  model-written explanation; **Ask** works as a streaming chat scoped to the active
  cluster's posture.
- API key never reaches the client; all calls go through the verified org; every call is
  audit-logged and counts against the rate limit and cost cap.
- Model output cites only IDs/assets present in the current scan (or explicitly says
  it doesn't); never proposes commands that mutate the cluster; never produces exploit
  code or payloads.
- The feature is behind `ff.aiNarration` and nothing deploys to production until you
  approve it.
