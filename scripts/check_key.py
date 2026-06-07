"""
NVD API key health check.

Pings the NVD CVE 2.0 API with a minimal request and writes the result to
data/health.json so the dashboard can show a live status pill.

Behavior:
- Reads NVD_API_KEY from the environment (provided by GitHub Actions secret).
- Requests 1 record from NVD with the key in the apiKey header.
- Retries up to 3 times on 429 / 5xx before giving up.
- Inspects the response status and X-RateLimit-Limit header.
- Writes (or merges into) data/health.json.
- Exits 0 on valid, non-zero on missing/invalid/error.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ROOT      = Path(__file__).resolve().parents[1]
HEALTH_FILE = ROOT / "data" / "health.json"
MAX_RETRIES = 3
RETRY_SLEEP = 8  # seconds between retries on 429 / 5xx


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_existing() -> dict[str, Any]:
    if HEALTH_FILE.exists():
        try:
            return json.loads(HEALTH_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def write_health(payload: dict[str, Any]) -> None:
    HEALTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HEALTH_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")


def ping_nvd(api_key: str):
    """Return requests.Response. Retries on 429 / 5xx up to MAX_RETRIES times."""
    headers = {"apiKey": api_key, "User-Agent": "automotive-cyber-dashboard/1.0"}
    params  = {"resultsPerPage": 1, "startIndex": 0}
    last_resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.get(NVD_URL, headers=headers, params=params, timeout=20)
        last_resp = resp
        if resp.status_code == 429 or (500 <= resp.status_code < 600):
            wait = RETRY_SLEEP * attempt
            print(f"[check_key] HTTP {resp.status_code} on attempt {attempt}/{MAX_RETRIES} — retrying in {wait}s")
            time.sleep(wait)
            continue
        break  # 2xx, 401, 403 — no retry
    return last_resp


def main() -> int:
    existing = load_existing()
    api_key  = os.environ.get("NVD_API_KEY", "").strip()

    payload: dict[str, Any] = {
        "checked_at": now_iso(),
        "key": {
            "status": "missing",
            "message": "NVD_API_KEY env var is empty.",
            "rate_limit": None,
            "http_status": None,
        },
        "fetch": existing.get("fetch", {"status": "never_run"}),
    }

    if not api_key:
        write_health(payload)
        print("[check_key] NVD_API_KEY is empty - status=missing")
        return 2

    try:
        resp = ping_nvd(api_key)
    except requests.RequestException as e:
        payload["key"] = {
            "status": "error",
            "message": f"Network error: {e}",
            "rate_limit": None,
            "http_status": None,
        }
        write_health(payload)
        print(f"[check_key] network error: {e}")
        return 3

    rate_limit_hdr = resp.headers.get("X-RateLimit-Limit")
    try:
        rate_limit = int(rate_limit_hdr) if rate_limit_hdr else None
    except ValueError:
        rate_limit = None

    if resp.status_code in (401, 403):
        payload["key"] = {
            "status": "invalid",
            "message": (
                f"NVD rejected the key (HTTP {resp.status_code}). "
                "Check the value of the NVD_API_KEY secret and that you have "
                "clicked the activation link NIST emailed when you registered."
            ),
            "rate_limit": rate_limit,
            "http_status": resp.status_code,
        }
        write_health(payload)
        print(f"[check_key] invalid key (HTTP {resp.status_code})")
        return 4

    if resp.status_code == 429:
        payload["key"] = {
            "status": "error",
            "message": f"NVD rate-limited after {MAX_RETRIES} retries (HTTP 429). Try again later.",
            "rate_limit": rate_limit,
            "http_status": 429,
        }
        write_health(payload)
        print("[check_key] rate-limited after retries")
        return 6

    if resp.status_code != 200:
        payload["key"] = {
            "status": "error",
            "message": f"Unexpected HTTP {resp.status_code} from NVD after {MAX_RETRIES} retries.",
            "rate_limit": rate_limit,
            "http_status": resp.status_code,
        }
        write_health(payload)
        print(f"[check_key] unexpected status {resp.status_code}")
        return 5

    try:
        body  = resp.json()
        total = body.get("totalResults")
    except Exception:
        total = None

    msg_parts = ["Key accepted by NVD."]
    if rate_limit:
        msg_parts.append(f"Rate limit: {rate_limit}/30s.")
        if rate_limit < 50:
            msg_parts.append("(Public limit — key may not be activated yet.)")
    if total is not None:
        msg_parts.append(f"NVD reports {total:,} total CVEs.")

    payload["key"] = {
        "status": "valid",
        "message": " ".join(msg_parts),
        "rate_limit": rate_limit,
        "http_status": 200,
    }
    write_health(payload)
    print("[check_key] OK -", payload["key"]["message"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
