from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schemas.finding import Finding


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


class EvidenceStore:
    def __init__(self, output_dir: str, task_id: str) -> None:
        self.root = Path(output_dir) / task_id / "evidence"
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, finding: Finding) -> str:
        payload = {
            "fingerprint": finding.fingerprint,
            "source": finding.source,
            "host": finding.host,
            "url": finding.url,
            "port": finding.port,
            "vuln_type": finding.vuln_type,
            "severity": finding.severity,
            "evidence": finding.evidence,
            "raw": finding.raw,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        encoded = _canonical(finding.evidence)
        evidence_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        finding.evidence_hash = evidence_hash
        path = self.root / f"{evidence_hash}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return evidence_hash

    def write_index(self, findings: list[Finding]) -> Path:
        rows = [
            {
                "fingerprint": item.fingerprint,
                "evidence_hash": item.evidence_hash,
                "source": item.source,
                "vuln_type": item.vuln_type,
                "severity": item.severity,
            }
            for item in findings
        ]
        path = self.root / "evidence_index.json"
        path.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path

    def read_verified(self, evidence_hash: str) -> dict[str, Any]:
        if not evidence_hash or not all(char in "0123456789abcdef" for char in evidence_hash):
            raise FileNotFoundError(evidence_hash)
        path = self.root / f"{evidence_hash}.json"
        if not path.exists():
            raise FileNotFoundError(evidence_hash)
        payload = json.loads(path.read_text(encoding="utf-8"))
        encoded = _canonical(payload.get("evidence", {}))
        actual = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if actual != evidence_hash:
            raise ValueError("evidence hash mismatch")
        return payload

    def find_by_fingerprint(self, fingerprint: str) -> str | None:
        path = self.root / "evidence_index.json"
        if not path.exists():
            return None
        rows = json.loads(path.read_text(encoding="utf-8"))
        return next(
            (
                str(item["evidence_hash"])
                for item in rows
                if item.get("fingerprint") == fingerprint
            ),
            None,
        )
