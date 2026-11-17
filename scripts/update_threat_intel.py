from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx


def fetch_epss(cve: str) -> float | None:
    response = httpx.get(
        f"https://api.first.org/data/v1/epss?cve={cve}",
        timeout=20,
    )
    response.raise_for_status()
    rows = response.json().get("data", [])
    return float(rows[0]["epss"]) if rows else None


def fetch_cvss(cve: str) -> float | None:
    response = httpx.get(
        f"https://cve.circl.lu/api/cve/{cve}",
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    value = payload.get("cvss") if isinstance(payload, dict) else None
    return float(value) if value is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update optional CVSS/EPSS cache without blocking scans."
    )
    parser.add_argument("--cves", nargs="*", default=[])
    parser.add_argument(
        "--output",
        default="config/cvss_epss_cache.json",
    )
    args = parser.parse_args()
    entries: dict[str, dict[str, float | None]] = {}
    errors: list[str] = []
    for cve in args.cves:
        cve = cve.strip().upper()
        entry: dict[str, float | None] = {
            "cvss_base": None,
            "epss_30d": None,
        }
        try:
            entry["cvss_base"] = fetch_cvss(cve)
        except Exception as exc:
            errors.append(f"{cve} CVSS: {exc}")
        try:
            entry["epss_30d"] = fetch_epss(cve)
        except Exception as exc:
            errors.append(f"{cve} EPSS: {exc}")
        entries[cve] = entry
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "FIRST EPSS",
        "entries": entries,
        "errors": errors,
    }
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
