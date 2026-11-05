"""Ekshop Site Sentinel - main entrypoint (cron-driven).

Usage:
    python -m sentinel init-db           # initialise SQLite state database
    python -m sentinel baseline          # record a fresh baseline
    python -m sentinel run                 # run full check + report
    python -m sentinel canary            # run the honeytoken admin canary check
"""

import sys
import os
import sqlite3
import hashlib
import json
import argparse
from datetime import datetime

# Add repo root to path
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

from config import settings
from baseline import record_baseline
from beacon import verify_beacon
from report import render_digest
from canary import run_canary

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
import argparse

parser = argparse.ArgumentParser(description="Ekshop Site Sentinel")
subparsers = parser.add_subparsers(dest="command")

# init-db subcommand
subparsers.add_parser("init-db", help="initialise SQLite state database")

# baseline subcommand
subparsers.add_parser("baseline", help="record a fresh baseline")

# run subcommand
subparsers.add_parser("run", help="run full check + report")

# canary subcommand
subparsers.add_parser("canary", help="run the honeytoken admin canary check")


# ---------------------------------------------------------------------------
# init-db
# ---------------------------------------------------------------------------
if sys.argv[1] == "init-db":
    db_path = os.path.join(REPO_ROOT, "state.sqlite")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS baselines ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "hash TEXT NOT NULL, "
        "recorded_at TEXT NOT NULL, "
        "source TEXT NOT NULL)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "type TEXT NOT NULL, "
        "severity TEXT NOT NULL, "
        "detail TEXT NOT NULL, "
        "recorded_at TEXT NOT NULL)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS canary ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "watermark TEXT NOT NULL, "
        "ip TEXT NOT NULL, "
        "ua TEXT NOT NULL, "
        "recorded_at TEXT NOT NULL)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS canary_alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "type TEXT NOT NULL, "
        "severity TEXT NOT NULL, "
        "detail TEXT NOT NULL, "
        "recorded_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()
    print("State database initialised at " + os.path.join(REPO_ROOT, "state.sqlite"))

# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------
elif sys.argv[1] == "baseline":
    h = record_baseline(settings)
    conn = sqlite3.connect(os.path.join(REPO_ROOT, "state.sqlite"))
    c = conn.cursor()
    c.execute(
        "INSERT INTO baselines (hash, recorded_at, source) VALUES (?, ?, ?)",
        (h, datetime.utcnow().isoformat(), "full_crawl")
    )
    conn.commit()
    conn.close()
    print("Baseline recorded: " + h[:16] + "...")

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
elif sys.argv[1] == "run":
    # 1. Verify integrity beacon
    beacon_ok, beacon_detail = verify_beacon(settings)

    # 2. Compare against last baseline
    db_path = os.path.join(REPO_ROOT, "state.sqlite")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT hash FROM baselines ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    baseline_hash = row[0] if row else None

    drift_notes = []
    if baseline_hash and baseline_hash != settings.last_baseline_hash:
        drift_notes.append(
            "Baseline hash differs from last recorded - possible configuration drift or content update."
        )

    # 3. Run canary
    canary_ok, canary_detail, canary_extra = run_canary(settings)

    # 4. Render markdown digest
    alerts = []
    if not beacon_ok:
        alerts.append({"type": "integrity_beacon", "severity": "critical", "detail": beacon_detail})
    if not canary_ok:
        alerts.append({"type": "canary", "severity": "critical", "detail": canary_detail})
    for note in drift_notes:
        alerts.append({"type": "drift", "severity": "medium", "detail": note})

    out_path = os.path.join(REPO_ROOT, "reports", f"digest_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
    os.makedirs(os.path.join(REPO_ROOT, "reports"), exist_ok=True)
    render_digest(out_path, alerts, settings)

    # 5. Update last known baseline hash
    settings.set_last_baseline_hash(settings.last_baseline_hash or baseline_hash or "")
    print("Run complete. Digest written to " + out_path)
    if alerts:
        for a in alerts:
            print(" - " + a["type"] + ": " + a["detail"])

# ---------------------------------------------------------------------------
# canary
# ---------------------------------------------------------------------------
elif sys.argv[1] == "canary":
    ok, detail, extra = run_canary(settings)
    if ok:
        print("Canary: " + detail)
    else:
        print("Canary: " + detail)
    if settings.CANARY_EMAIL and not ok:
        print(" (would email alert to " + settings.CANARY_EMAIL + "): " + detail)
    sys.exit(0 if ok else 1)

# ---------------------------------------------------------------------------
# Unknown command
# ---------------------------------------------------------------------------
else:
    parser.print_help()
    sys.exit(1)

if __name__ == "__main__":
    main()