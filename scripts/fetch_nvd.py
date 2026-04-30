"""
Fetch CVEs from the NVD CVE 2.0 API for automotive OEMs and write to data/cves.json.

- Reads OEM keyword/ECU mapping from data/ecu_components.json
- Reads category -> compliance clause map from data/compliance_map.json
- For each OEM, queries NVD by keyword (one keyword per request, paginated)
- Normalizes results, deduplicates by CVE ID, infers ECU class + categories,
  attaches matched compliance clauses, and writes data/cves.json.

Run locally:
    pip install -r requirements.txt
    export NVD_API_KEY="your-key"     # PowerShell: $env:NVD_API_KEY="your-key"
    python scripts/fetch_nvd.py

In CI, NVD_API_KEY is provided by the GitHub Actions secret.
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

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200
# How far back to look. NVD allows up to 120 day windows; we paginate further by date if needed.
LOOKBACK_DAYS = int(os.environ.get("NVD_LOOKBACK_DAYS", "365"))
REQUEST_TIMEOUT = 30
SLEEP_BETWEEN_CALLS = 0.7  # NVD allows 50 req / 30s with API key; this stays well below.

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def log(msg: str) -> None:
    print(f"[fetch_nvd] {msg}", flush=True)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def call_nvd(keyword: str, api_key: str) -> list[dict[str, Any]]:
    """Fetch all NVD CVEs matching a keyword (last LOOKBACK_DAYS), paginated."""
    headers = {"apiKey": api_key, "User-Agent": "automotive-cyber-dashboard/1.0"}

    # NVD pubStartDate / pubEndDate window. We use a single window; for >120 days the
    # API requires splitting, so we cap at 120 days and accept the trade-off, with
    # multiple windows iterated below.
    end = datetime.now(timezone.utc)
    windows: list[tuple[datetime, datetime]] = []
    remaining = LOOKBACK_DAYS
    cur_end = end
    while remaining > 0:
        days = min(remaining, 120)
        cur_start = cur_end - _days(days)
        windows.append((cur_start, cur_end))
        cur_end = cur_start
        remaining -= days

    all_items: list[dict[str, Any]] = []
    for win_start, win_end in windows:
        start_index = 0
        while True:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
                "pubStartDate": win_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate":   win_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            }
            log(f"keyword={keyword!r} window={win_start.date()}..{win_end.date()} startIndex={start_index}")
            resp = requests.get(NVD_URL, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 403:
                log("403 from NVD - check that NVD_API_KEY is correct.")
                resp.raise_for_status()
            if resp.status_code == 429:
                log("429 rate-limited, sleeping 6s and retrying...")
                time.sleep(6)
                continue
            resp.raise_for_status()
            payload = resp.json()
            items = payload.get("vulnerabilities", []) or []
            total = payload.get("totalResults", 0)
            all_items.extend(items)
            start_index += PAGE_SIZE
            time.sleep(SLEEP_BETWEEN_CALLS)
            if start_index >= total:
                break
    return all_items


def _days(n: int):
    from datetime import timedelta
    return timedelta(days=n)


def extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {}) or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or severity_from_score(score)
            try:
                return float(score), str(severity).upper()
            except (TypeError, ValueError):
                pass
    return None, "UNKNOWN"


def english_description(cve: dict[str, Any]) -> str:
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def classify_ecu(text: str, ecu_classes: dict[str, dict]) -> tuple[str | None, list[str]]:
    """Return (ecu_class_id, matched_components) by simple substring search."""
    t = text.lower()
    best_class: str | None = None
    matched_components: list[str] = []
    for cls_id, cls in ecu_classes.items():
        for comp in cls.get("components", []):
            if comp.lower() in t:
                if best_class is None:
                    best_class = cls_id
                if comp not in matched_components:
                    matched_components.append(comp)
    return best_class, matched_components


def classify_categories(text: str, categories: list[dict]) -> list[str]:
    t = text.lower()
    hits: list[str] = []
    for cat in categories:
        match = cat.get("match", {}) or {}
        kws = [k.lower() for k in match.get("keywords", [])]
        if any(k in t for k in kws):
            hits.append(cat["id"])
    return hits


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if not api_key:
        log("ERROR: NVD_API_KEY env var is empty. Set it as a GitHub Actions secret or local env var.")
        return 2

    ecu_map = load_json(DATA_DIR / "ecu_components.json")
    compliance_map = load_json(DATA_DIR / "compliance_map.json")
    categories = compliance_map.get("categories", [])

    # CVE id -> normalized record
    by_id: dict[str, dict[str, Any]] = {}

    for oem_id, oem in ecu_map.items():
        keywords = list(dict.fromkeys(oem.get("keywords", []) + oem.get("suppliers", [])))
        for kw in keywords:
            try:
                items = call_nvd(kw, api_key)
            except Exception as e:
                log(f"keyword={kw!r} failed: {e}")
                continue
            for item in items:
                cve = item.get("cve", {}) or {}
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                desc = english_description(cve)
                score, severity = extract_cvss(cve)
                ecu_class, components = classify_ecu(desc, oem.get("ecu_classes", {}))
                cats = classify_categories(desc, categories)

                if cve_id in by_id:
                    rec = by_id[cve_id]
                    if oem_id not in rec["matched_oems"]:
                        rec["matched_oems"].append(oem_id)
                    if kw.lower() not in [k.lower() for k in rec["matched_keywords"]]:
                        rec["matched_keywords"].append(kw)
                    for c in components:
                        if c not in rec["components"]:
                            rec["components"].append(c)
                    for cat in cats:
                        if cat not in rec["categories"]:
                            rec["categories"].append(cat)
                    if rec["ecu_class"] is None:
                        rec["ecu_class"] = ecu_class
                else:
                    by_id[cve_id] = {
                        "id": cve_id,
                        "published": (cve.get("published") or "")[:10],
                        "modified":  (cve.get("lastModified") or "")[:10],
                        "cvss": score,
                        "severity": severity,
                        "description": desc,
                        "matched_oems": [oem_id],
                        "matched_keywords": [kw],
                        "ecu_class": ecu_class,
                        "components": components,
                        "categories": cats,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }

    cves = sorted(by_id.values(), key=lambda r: (r["published"] or ""), reverse=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "nvd-cve-2.0",
        "lookback_days": LOOKBACK_DAYS,
        "count": len(cves),
        "cves": cves,
    }
    save_json(DATA_DIR / "cves.json", payload)
    log(f"wrote {len(cves)} CVEs to data/cves.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
