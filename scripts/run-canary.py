"""Run the honeytoken admin canary check.

Emits a watermark-signed request to the market-expansion endpoint
and records the result in the state database.

Usage:
    python scripts/run-canary.py
"""

import os
import hashlib
import httpx
from datetime import datetime

from config import settings

API_BASE = settings.API_BASE_URL.rstrip("/") if settings.API_BASE_URL else ""
if not API_BASE:
    print("SENTINEL_API_URL not configured - cannot run canary.")
    exit(1)

WATERMARK = os.getenv("CANARY_WATERMARK", "")
if not WATERMARK:
    WATERMARK = hashlib.sha256(os.urandom(16)).hexdigest()[:16]

BEACON_URL = API_BASE + "/admin/metrics/market-expansion"
WATERMARK_URL = BEACON_URL + ("?x-canary=" + WATERMARK if "?" in BEACON_URL else "?x-canary=" + WATERMARK)

def main():
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(WATERMARK_URL, follow_redirects=True)
            if resp.status_code != 200:
                print("Canary probe returned HTTP " + str(resp.status_code))
                exit(1)

            payload = resp.json()
            # Record watermark in DB (simple append)
            import sqlite3
            DB_PATH = os.path.join(os.path.dirname(__file__), "..", "state.sqlite")
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("CREATE TABLE IF NOT EXISTS canary (id INTEGER PRIMARY KEY AUTOINCREMENT, watermark TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL, recorded_at TEXT NOT NULL)")
            c.execute("INSERT INTO canary (watermark, ip, ua, recorded_at) VALUES (?, ?, ?, ?)",
                      (WATERMARK, "unknown", "sentinel-canary", datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
            print("Canary probe OK - watermark recorded: " + WATERMARK[:16] + "...")
    except Exception as e:
        print("Canary probe failed: " + str(e))
        exit(1)

if __name__ == "__main__":
    main()