from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.finding import Finding
from app.schemas.task import TaskCreate


def test_finding_fingerprint_is_deterministic() -> None:
    payload = {
        "source": "nuclei",
        "host": "dvwa",
        "url": "http://dvwa/index.php",
        "port": 80,
        "vuln_type": "Example Finding",
        "severity": "medium",
    }
    left = Finding(**payload)
    right = Finding(**payload)

    assert left.fingerprint == right.fingerprint
    assert len(left.fingerprint) == 32


def test_task_model_leaves_rate_policy_to_guard() -> None:
    task = TaskCreate(
        target="http://dvwa",
        auth_ref="local-dvwa",
        max_rps=100,
        mode="active",
    )

    assert task.max_rps == 100


def test_oast_requires_deep_validation() -> None:
    with pytest.raises(ValidationError):
        TaskCreate(
            target="http://dvwa",
            auth_ref="local-dvwa",
            validation_level="safe",
            oast_enabled=True,
        )
