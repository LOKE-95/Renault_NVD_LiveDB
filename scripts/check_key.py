"""
NVD API key health check.

Pings the NVD CVE 2.0 API with a minimal request and writes the result to
data/health.json so the dashboard can show a live status pill.

Behavior:
- Reads NVD_API_KEY from the environment (provided by GitHub Actions secret).
- Requests 1 record from NVD with the key in the apiKey header.
- Inspects the response status and X-RateLimit-Limit header.
- Writes (or merges into) data/health.json:
    {
      "checked_at": "<ISO timestamp>",
      "key": {
        "status": "valid" | "invalid" | "missing" | "error",
        "message": "<human-readable>",
        "rate_limit": <int|null>,
        "http_status": <int|null>
      },
      "fetch": { ...preserved from previous run if any... }
    }
- Exits 0 on valid, non-zero on missing/invalid/error so the workflow can
  decide whether to skip the heavy fetch step.

Run locally:
    pip install -r requirements.txt
    export NVD_API_KEY="your-key"     # PowerShell: $env:NVD_API_KEY="your-key"
    python scripts/check_key.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ROOT = Path(__file__).resolve().parents[1]
HEALTH_FILE = ROOT / "data" / "health.json"


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


def main() -> int:
    existing = load_existing()
    api_key = os.environ.get("NVD_API_KEY", "").strip()

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
        resp = requests.get(
            NVD_URL,
            headers={"apiKey": api_key, "User-Agent": "automotive-cyber-dashboard/1.0"},
            params={"resultsPerPage": 1, "startIndex": 0},
            timeout=20,
        )
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
                "Check the value of the NVD_API_KEY secret and that you've "
                "clicked the activation link NIST emailed when you registered."
            ),
            "rate_limit": rate_limit,
            "http_status": resp.status_code,
        }
        write_health(payload)
        print(f"[check_key] invalid key (HTTP {resp.status_code})")
        return 4

    if resp.status_code != 200:
        payload["key"] = {
            "status": "error",
            "message": f"Unexpected HTTP {resp.status_code} from NVD.",
            "rate_limit": rate_limit,
            "http_status": resp.status_code,
        }
        write_health(payload)
        print(f"[check_key] unexpected status {resp.status_code}")
        return 5

    # 200 OK - confirm body shape and rate-limit ceiling
    try:
        body = resp.json()
        total = body.get("totalResults")
    except Exception:
        total = None

    msg_parts = ["Key accepted by NVD."]
    if rate_limit:
        msg_parts.append(f"Rate limit: {rate_limit}/30s.")
        if rate_limit < 50:
            msg_parts.append("(Public limit is 5 - your key may not be activated.)")
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
