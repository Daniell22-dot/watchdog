"""Run the baseline profiler.

Fetches key Ekshop pages (public + admin routes) and records
SHA-256 hashes to the state database.

Usage:
    python scripts/run-baseline.py
"""

import os
import hashlib
import httpx
from datetime import datetime

from config import settings
from report import render_digest

PUBLIC_URL = settings.API_BASE_URL.rstrip("/") if settings.API_BASE_URL else ""
ADMIN_BASE = PUBLIC_URL.rstrip("/") + "/admin" if PUBLIC_URL else ""

PUBLIC_ENDPOINTS = [
    "/",
    "/cart",
    "/accounts/login",
]

ADMIN_ENDPOINTS = [
    "/metrics/market-expansion",
    "/stats",
    "/stats/overview",
]

def fetch_and_hash(client: httpx.Client, url: str) -> str | None:
    try:
        resp = client.get(url, timeout=15)
        if resp.status_code >= 200 and resp.status_code < 300:
            return hashlib.sha256(resp.text.encode("utf-8")).hexdigest()
    except Exception:
        pass
    return None

def record_baseline() -> str:
    endpoints = {}
    with httpx.Client(timeout=20) as client:
        for ep in PUBLIC_ENDPOINTS:
            full = (PUBLIC_URL.rstrip("/") + ep) if PUBLIC_URL else ""
            if full:
                h = fetch_and_hash(client, full)
                if h:
                    endpoints[ep] = h

        for ep in ADMIN_ENDPOINTS:
            full = (ADMIN_BASE.rstrip("/") + ep) if ADMIN_BASE else ""
            if full:
                h = fetch_and_hash(client, full)
                if h:
                    endpoints[ep] = h

    sorted_items = sorted(endpoints.items())
    concat = "".join(h for _, h in sorted_items)
    composite = hashlib.sha256(concat.encode("utf-8")).hexdigest()
    return composite

if __name__ == "__main__":
    h = record_baseline()
    import sqlite3
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "state.sqlite")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO baselines (hash, recorded_at, source) VALUES (?, ?, ?)",
              (h, datetime.utcnow().isoformat(), "full_crawl"))
    conn.commit()
    conn.close()
    print("Baseline recorded: " + h[:16] + "...")