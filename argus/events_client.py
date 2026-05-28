"""argus/events_client.py — minimal POST helper for the pubkey-connect
control-plane API.

Stdlib only (urllib) so we don't add a top-level dep. Matches the FROZEN wire
contract in ``docs/PUBKEY_CONNECT_CONTRACT.md`` byte-for-byte:

  * Auth:        ``Authorization: Bearer ent_<raw>``
  * Content:     ``application/json``
  * Timeout:     10s
  * Retry:       single retry on 5xx (linear backoff 500ms)

All callers are responsible for never leaking the enrollment token or any
secret material into the ``detail`` payload — we don't redact here.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Optional

log = logging.getLogger(__name__)

_TIMEOUT = 10.0
_RETRY_BACKOFF = 0.5
_MAX_DETAIL_BYTES = 2048  # contract §2: detail bodies must keep frame ≤ 2 KB


class EventsClientError(RuntimeError):
    """Raised when the control-plane API rejects the request after retries."""


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def post_event(
    control_plane: str,
    cluster_id: str,
    token: str,
    event_type: str,
    detail: Optional[dict] = None,
) -> None:
    """POST ``/api/clusters/<cluster_id>/events``. Returns on 2xx, raises on
    4xx; retries once on 5xx. Truncates ``detail`` if it exceeds 2 KB.

    Per contract §2, the response is 204 — we don't return anything on
    success.
    """
    payload = {"type": event_type, "detail": _bounded_detail(detail or {})}
    url = _join(control_plane, f"/api/clusters/{cluster_id}/events")
    body, status = _post_json(url, token, payload)
    if status >= 400:
        raise EventsClientError(
            f"event POST failed ({status}) for type={event_type!r}: {body[:300]!r}"
        )


def post_scan(
    control_plane: str,
    cluster_id: str,
    token: str,
    report: dict,
) -> dict:
    """POST ``/api/scans``. Contract §3 — body is
    ``{ clusterId, report }``; returns ``{ scanId, createdAt }``.
    """
    payload = {"clusterId": cluster_id, "report": report}
    url = _join(control_plane, "/api/scans")
    body, status = _post_json(url, token, payload)
    if status >= 400:
        raise EventsClientError(f"scan POST failed ({status}): {body[:300]!r}")
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise EventsClientError(f"scan POST returned non-JSON body: {body[:200]!r}") from e


def resolve_cluster_id(control_plane: str, token: str) -> str:
    """Resolve our own cluster id from the enrollment token.

    The contract leaves clusterId acquisition ambiguous: ``POST /api/clusters``
    returns ``{ id, enrollmentToken }`` to the *web user*, but the CLI only
    ever sees the raw enrollment token. We use a GET to
    ``/api/clusters/_self`` with the Bearer token; the control-plane resolves
    the token → enrollment row → cluster_id.

    If the control-plane hasn't implemented ``_self`` yet, callers should set
    ``ARGUS_CLUSTER_ID`` env var as an escape hatch (handled in
    bootstrap.py). This function only handles the network path.
    """
    url = _join(control_plane, "/api/clusters/_self")
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = resp.read().decode("utf-8")
            body = json.loads(data)
            cid = body.get("id") or body.get("clusterId")
            if not cid:
                raise EventsClientError(
                    f"/api/clusters/_self response missing 'id': {body!r}"
                )
            return str(cid)
    except urllib.error.HTTPError as e:
        raise EventsClientError(
            f"/api/clusters/_self returned {e.code}: {e.read()[:200]!r}"
        ) from e
    except urllib.error.URLError as e:
        raise EventsClientError(f"/api/clusters/_self failed: {e}") from e


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _post_json(url: str, token: str, payload: Any) -> tuple[str, int]:
    """POST JSON with a single retry on 5xx. Returns (body_str, status)."""
    body_bytes = json.dumps(payload, default=str).encode("utf-8")
    last_err: Optional[Exception] = None
    for attempt in (0, 1):
        try:
            req = urllib.request.Request(url, data=body_bytes, method="POST")
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return resp.read().decode("utf-8"), resp.status
        except urllib.error.HTTPError as e:
            # 5xx → retry once; 4xx → surface immediately.
            status = getattr(e, "code", 500)
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            if status >= 500 and attempt == 0:
                log.warning("control-plane %s returned %s; retrying", url, status)
                time.sleep(_RETRY_BACKOFF)
                last_err = e
                continue
            return body, status
        except urllib.error.URLError as e:
            if attempt == 0:
                log.warning("control-plane %s unreachable (%s); retrying", url, e)
                time.sleep(_RETRY_BACKOFF)
                last_err = e
                continue
            raise EventsClientError(f"control-plane unreachable: {e}") from e
    raise EventsClientError(f"control-plane failed after retry: {last_err}")


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + path


def _bounded_detail(detail: dict) -> dict:
    """Drop the frame to ≤ 2 KB JSON. Strategy: if oversize, replace the
    longest string value with a truncation marker and recheck. Worst case
    return ``{"truncated": True}``."""
    try:
        encoded = json.dumps(detail, default=str)
    except (TypeError, ValueError):
        return {"truncated": True, "reason": "non-serializable"}

    if len(encoded.encode("utf-8")) <= _MAX_DETAIL_BYTES:
        return detail

    truncated = dict(detail)
    while True:
        encoded = json.dumps(truncated, default=str)
        if len(encoded.encode("utf-8")) <= _MAX_DETAIL_BYTES:
            return truncated
        # Find the longest string value and replace it.
        longest_key = None
        longest_len = 0
        for k, v in truncated.items():
            if isinstance(v, str) and len(v) > longest_len:
                longest_key = k
                longest_len = len(v)
        if longest_key is None:
            return {"truncated": True, "reason": "oversize"}
        truncated[longest_key] = truncated[longest_key][:200] + "…[truncated]"
        # Safety: if we still can't shrink, bail.
        if json.dumps(truncated, default=str) == encoded:
            return {"truncated": True, "reason": "oversize"}
