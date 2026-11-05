"""Ekshop Site Sentinel â€” main entrypoint.

Cronâ€‘driven (e.g. via systemd timer or Task Scheduler) to:
  1. Record a fresh baseline (public site + admin dashboard).
  2. Run integrity beacon verification.
  3. Output a markdown digest under reports/.

Usage:
    python -m sentinel init-db     # initialise SQLite state
    python -m sentinel baseline    # record a fresh baseline
    python -m sentinel run         # run full check + report
"""

import sys
import os
import sqlite3
import hashlib
import json
from datetime import datetime

# Add repo root to path
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

from config import settings
from baseline import record_baseline
from beacon import verify_beacon
from report import render_digest

# settings is the module-level settings() from config.py

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m sentinel init-db        # initialise SQLite state database")
        print("  python -m sentinel baseline       # record a fresh baseline")
        print("  python -m sentinel run            # run full check + report")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init-db":
        db_path = os.path.join(REPO_ROOT, "state.sqlite")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            source TEXT NOT NULL
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )""")
        conn.commit()
        conn.close()
        print("âœ… State database initialised at", db_path)

    elif command == "baseline":
        from datetime import datetime as _dt
        h = record_baseline(settings)
        conn = sqlite3.connect(os.path.join(REPO_ROOT, "state.sqlite"))
        c = conn.cursor()
        c.execute("INSERT INTO baselines (hash, recorded_at, source) VALUES (?, ?, ?)",
                  (h, _dt.utcnow().isoformat(), "full_crawl"))
        conn.commit()
        conn.close()
        print(f"âœ… Baseline recorded: {h[:16]}â€¦")

    elif command == "run":
        # 1. Verify integrity beacon
        beacon_ok, beacon_detail = verify_beacon(settings)

        # 2. Compare against last baseline (simple distance check)
        db_path = os.path.join(REPO_ROOT, "state.sqlite")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT hash FROM baselines ORDER BY id DESC LIMIT 1")
        row = c.fetchone()
        baseline_hash = row[0] if row else None

        drift_notes = []
        if baseline_hash and baseline_hash != settings.get("last_baseline_hash", ""):
            drift_notes.append("Baseline hash differs from last recorded â€” possible configuration drift or content update.")

        # 3. Render markdown digest
        alerts = []
        if not beacon_ok:
            alerts.append({
                "type": "integrity_beacon",
                "severity": "critical",
                "detail": beacon_detail
            })
        for note in drift_notes:
            alerts.append({
                "type": "drift",
                "severity": "medium",
                "detail": note
            })

        out_path = os.path.join(REPO_ROOT, "reports", f"digest_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
        os.makedirs(os.path.join(REPO_ROOT, "reports"), exist_ok=True)
        render_digest(out_path, alerts, settings)

        # 4. Update last known baseline hash in settings (for next run)
        settings["last_baseline_hash"] = settings.get("last_baseline_hash", baseline_hash or "")
        # In a real deployment you'd persist this; here we just note it.
        print(f"âœ… Run complete. Digest written to {out_path}")
        if alerts:
            for a in alerts:
                print(f"  âš ï¸  [{a['severity']}] {a['type']}: {a['detail']}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
