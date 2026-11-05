"""Initialize the Sentinel SQLite state database.

Run once to set up the required tables for baseline hashes,
canary records, and alerts.
"""

import sqlite3
import os
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(REPO_ROOT, "state.sqlite")

def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            source TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS canary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            watermark TEXT NOT NULL,
            ip TEXT NOT NULL,
            ua TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS canary_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            detail TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("State database initialised at " + DB_PATH)

if __name__ == "__main__":
    main()