"""Baseline profiler — records HTML/SHA‑256 hashes of key Ekshop pages.

Reads only; never modifies the Ekshop app state. Writes to the sentinel's
SQLite state database (state.sqlite) under the `baselines` table.
"""

import os
import hashlib
import httpx
from datetime import datetime
from config import settings

PUBLIC_URL = settings.API_BASE_URL.rstrip("/") if settings.API_BASE_URL else ""
ADMIN_BASE = PUBLIC_URL.rstrip("/") + "/admin" if PUBLIC_URL else ""

# Pages/endpoints to hash (relative to the base URL).
PUBLIC_ENDPOINTS = [
    "/",                                            # home / catalog
    "/cart",                                        # cart page
    "/accounts/login",                              # login
]

ADMIN_ENDPOINTS = [
    "/metrics/market-expansion",                    # market‑expansion tab
    "/stats",                                       # admin stats
    "/stats/overview",                              # admin overview
]

def _fetch_and_hash(client: httpx.Client, url: str) -> str | None:
    """GET *url*, return SHA‑256 hex of the response body, or None on error."""
    try:
        resp = client.get(url, timeout=15)
        if resp.status_code >= 200 and resp.status_code < 300:
            return hashlib.sha256(resp.text.encode("utf-8")).hexdigest()
    except Exception:
        pass
    return None

def record_baseline(settings) -> str:
    """Fetch all profiled endpoints, compute hashes, return a single composite hash.

    Returns a SHA‑256 hash of the concatenated endpoint hashes (sorted by name)
    so the baseline is deterministic regardless of fetch order.
    """
    endpoints = {}
    with httpx.Client(timeout=20) as client:
        # Public endpoints
        for ep in PUBLIC_ENDPOINTS:
            full = (PUBLIC_URL.rstrip("/") + ep) if PUBLIC_URL else ""
            if full:
                h = _fetch_and_hash(client, full)
                if h:
                    endpoints[ep] = h

        # Admin endpoints (only if API base is set; may return 401/403 — that's ok)
        for ep in ADMIN_ENDPOINTS:
            full = (ADMIN_BASE.rstrip("/") + ep) if ADMIN_BASE else ""
            if full:
                h = _fetch_and_hash(client, full)
                if h:
                    endpoints[ep] = h

    # Deterministic ordering
    sorted_items = sorted(endpoints.items())
    concat = "".join(h for _, h in sorted_items)
    composite = hashlib.sha256(concat.encode("utf-8")).hexdigest()
    return composite