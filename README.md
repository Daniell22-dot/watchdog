# Ekshop Site Sentinel

## Overview

**Ekshop Site Sentinel** is a standalone, offline-first security monitor for the Ekshop e-commerce platform (admin dashboard + public site). It detects configuration drift, malicious behaviour, and security regressions — acting as an independent observer so that compromise of the Ekshop infra does not blind the monitor.

The sentinel is deployed on a **separate host/credentials boundary** and only reads data — it never sends requests that modify state.

### Core Philosophy

- **Read-only**: fetches pages & verifies signatures; never posts or mutates.
- **Privacy-preserving**: stores only hashes, never full cookies or secrets.
- **Cron-driven**: runs on a schedule (e.g. daily via systemd timer or Task Scheduler).
- **Defense-in-depth**: combines multiple independent checks (beacon, baseline drift, canary, attestation) so no single failure blinds the monitor.

### Deployed Configuration (D:\EKSHOP-SENTINEL)

The repo at `D:\EKSHOP-SENTINEL` ships with the following protections **enabled by default**:

| Feature | Description | Status |
|---|---|---|
| **Integrity Beacon** | The backend signs `GET /admin/metrics/market-expansion` with Ed25519; the sentinel verifies the signature and checks that `coverage_error` is benign (never the "bundle is missing" lie). | ✅ Enabled |
| **Interaction‑Entropy Attestation** (novel) | On every admin‑page render, a hashed pointer‑move event is injected into the DOM; the sentinel headless browser records the `clientX/clientY` hash; if a subsequent session’s hash falls outside ±3σ of the baseline, it indicates a non‑human or replayed session — mitigates Binance‑style stolen‑API‑key replay. | ✅ Enabled |
| **Baseline Profiler** | Weekly crawl of public site + `/admin/*` routes; records SHA‑256 hashes of key pages, CSP/Strict‑Transport‑Security/Permissions‑Policy headers, response times, cookie names, DNS records. | ✅ Enabled |
| **Honeytoken Canary** (optional) | A dedicated `canary@ekshop.store` account; daily login records JWT + session cookie; any login from an unexpected IP/UA or the canary watermark token appearing in a non‑canary request triggers Critical alert. | ⚙️ Enable via `CANARY_EMAIL` env var |
| **Egress Behaviour Monitor** (optional) | If run with `mitmproxy` in transparent mode, records all outbound DNS/SSL connections from the admin browser; flags any connection to a host not in a strict whitelist. | ⚙️ Enable via `CAN_ENABLE_EGRESS=1` |

### Repo Layout (`D:\EKSHOP-SENTINEL`)

```
EKSHOP-SENTINEL/
├─ sentinel.py                # main entrypoint (cron‑driven: init-db, baseline, run)
├─ baseline.py                # baseline profiler + hash storage
├─ beacon.py                  # integrity‑JWT verification + payload sanity
├─ attestation.py             # interaction‑entropy hash collection (optional;
|   # see README for how to enable/disable; currently integrated into sentinel.py
├─ canary.py                  # honeytoken admin canary (optional; wired into sentinel.py
|   # via ENABLE_ATTESTATION flag and CANARY_EMAIL)
├─ egress.py                 # optional outbound monitor (mitmproxy hook; wired via
|   # CAN_ENABLE_EGRESS env var)
├─ config.py                 # read ONLY from env; never commit secrets
├─ requirements.txt
├─ .env.example              # placeholders: SENTINEL_API_URL, CANARY_EMAIL
├─ .gitignore
├─ scripts/
|  └─ init-db.py
└─ reports/                   # generated markdown digests (git‑ignored)
```

### Quick Start

```powershell
# 1. Initialise the SQLite state database
python -m sentinel init-db

# 2. Record a fresh baseline (public site + admin dashboard)
python -m sentinel baseline

# 3. Run the full check (beacon verification + drift report)
python -m sentinel run

# 4. View the markdown digest under reports/
```

### Environment Variables (`.env` — never commit)

| Variable | Required? | Default | Description |
|---|---|---|---|
| `SENTINEL_API_URL` | ✅ yes | — | The base URL of the Ekshop API (e.g. `http://localhost:8000` or `https://ekshop.example.com`). |
| `CANARY_EMAIL` | optional | `` | Email address for canary‑alert notifications. |
| `CAN_ENABLE_ATTESTATION` | ✅ recommended | `1` | Set to `0` to disable interaction‑entropy attestation. |
| `CAN_ENABLE_EGRESS` | optional | `0` | Set to `1` to enable the outbound egress monitor (requires mitmproxy). |
| `SECRET_KEY` | ✅ yes (for beacon signature verification) | — | The Ed25519 secret key used by the Ekshop backend; must match the instance's `SECRET_KEY` in `app/core/config.py`. |

### Interaction‑Entropy Attestation (the "best" novel protection)

This is the centrepiece of the sentinel's defence-in-depth strategy.

1. **Injection**: On every render of any `/admin/*` page, a tiny JavaScript snippet fires in the headless browser:

   ```js
   window.dispatchEvent(new PointerEvent('pointermove', {
       clientX: Math.random() * window.innerWidth,
       clientY: Math.random() * window.innerHeight,
       type: 'pointermove'
   }));
   ```

2. **Recording**: The sentinel's `baseline.py` captures the `clientX/clientY` values on first baseline run and stores their SHA‑256 hash.

3. **Monitoring**: On each subsequent `run`, the sentinel re‑captures the hashes and compares them against the baseline using ±3σ (three‑standard‑deviation) thresholds.

4. **Alert condition**: If a new session's hash falls outside the threshold, a **Critical** alert is generated: `"Interaction entropy deviates from baseline — possible non‑human or replayed session"`.

**Why this is novel**: Most site monitors only check HTTP responses. By measuring behavioural biometrics of the rendered page (hashed pointer coordinates), we detect session replay/automation that static hash‑checking misses. This directly mitigates the Binance‑style stolen‑API‑key replay vector where an attacker lacks the original user's interaction patterns.

**Enabling/disabling**: Controlled by `CAN_ENABLE_ATTESTATION` env var (on by default). To disable, set `CAN_ENABLE_ATTESTATION=0`.

### Canary Admin Account (optional)

- Create a dedicated admin user: `canary@ekshop.store` with a random password.
- The sentinel logs in once per day (via API, no browser) and records the JWT + session cookie.
- The canary also embeds a watermark token (`?x‑canary=ABCD1234`) in the `GET /admin/metrics/market-expansion` response.
- **Alert conditions**:
  - Successful login from an unexpected IP, user‑agent, or geographic location.
  - The canary watermark token appears in a non‑canary request (signals session‑theft or log leakage).
- **Enable**: Set `CANARY_EMAIL` env var (alerts sent there) and ensure the canary account exists.
- **Disable**: Set `CAN_ENABLE_ATTESTATION=0` *and* remove/rename the canary account.

### Egress Behaviour Monitor (optional, on‑prem)

If the sentinel is run on a host with `mitmproxy` in transparent mode:

1. All outbound DNS/SSL connections from the admin browser during a dashboard session are recorded.
2. Any connection to a host **not** in the strict whitelist triggers a **Medium** alert:
   - Whitelist: `api.ekshop.store`, `s3.eu-west-1.amazonaws.com`, `cdn.jsdelivr.net`, `vercel.live`, `*.vercel.app`.
3. **Enable**: `CAN_ENABLE_EGRESS=1` env var.
4. **Dependencies**: `mitmproxy` must be installed and configured on the sentinel host; the sentinel reads its logs (`mitmproxy -l dump.log`).

### Reporting

Each `python -m sentinel run` generates a markdown file under `reports/digest_YYYYMMDD_HHMMSS.md` with:

- Run timestamp and API base URL.
- Last recorded baseline hash.
- Any alerts (beacon, drift, canary, attestation, egress).
- A quick‑look summary table.
- The file is also suitable for conversion to Word via pandoc (as documented in the main security audit).

### Security Considerations

- **Never commit `.env`** with real values. The `.env.example` contains only placeholders.
- The sentinel **stores no secrets**, passwords, or full cookie values. It records only names (and hashed pointers for attestation).
- Deploy on a **separate host or VM** to isolate trust boundaries. If the Ekshop infra is compromised, the sentinel remains a trustworthy observer (provided its own host is secure).
- The Ed25519 `SECRET_KEY` used for beacon signature verification must match the instance running Ekshop; rotate both in coordination.

### Future Extensions

- Integrate with SIEM/SLACK/Discord webhook for real‑time alerting.
- Add TLS‑fingerprint (JA3/JA4) checking alongside interaction entropy.
- Extend the egress monitor to decode and inspect application‑level protocols (e.g., detect crypto‑miner beacons).
- Port the attestation logic to a browser extension for in‑situ user‑side verification.

---

*This repo is the monitoring counterpart of the [Ekshop 2026 Security Audit](Ekshop-2026-Security-Audit.md). See the audit for the full findings, remediation priorities, and threat‑landscape context (PHP2Shell, npm supply‑chain 2026, Binance/Kenya incidents).*

*Generated 2026‑11‑04.*