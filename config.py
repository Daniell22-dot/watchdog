"""Sentinel configuration — read ONLY from environment variables.

Never commit a .env file with real values into this repo.
"""

import os
from datetime import datetime


class Settings:
    def __init__(self):
        # The Ekshop API base URL (must be set by the deployment).
        # Example: http://localhost:8000 or https://ekshop.example.com
        self.API_BASE_URL = os.getenv("SENTINEL_API_URL", "").rstrip("/")

        # Optional: email address for canary alert notifications.
        self.CANARY_EMAIL = os.getenv("CANARY_EMAIL", "")

        # Feature toggles (set via env: 1/true or 0/false).
        # CAN_ENABLE_ATTESTATION=1  # interaction-entropy attestation (recommended)
        # CAN_ENABLE_EGRESS=1        # outbound egress monitor (mitmproxy hook)
        # These are enabled by default in the shipped configuration for maximum security.
        self.ENABLE_ATTESTATION = os.getenv("CAN_ENABLE_ATTESTATION", "1").lower() in ("1", "true", "yes")
        self.ENABLE_EGRESS_MONITOR = os.getenv("CAN_ENABLE_EGRESS", "0").lower() in ("1", "true", "yes")

        # Cached last baseline hash (populated on first run).
        self.last_baseline_hash = os.getenv("SENTINEL_LAST_BASELINE", "")

        # Timestamp of last run, for drift detection.
        self.last_run_at = datetime.utcnow().isoformat()

    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        val = getattr(self, key, None)
        return val if val is not None else default

    def set_last_baseline(self, h):
        self.last_baseline_hash = h


# Global singleton — created once at module import.
settings = Settings()