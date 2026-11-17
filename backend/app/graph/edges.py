from __future__ import annotations

from .state import PentestState


def route_after_auth(state: PentestState) -> str:
    return "report" if state.get("status") == "blocked" else "recon"


def route_after_router(state: PentestState) -> str:
    return str(state.get("next_scan_node") or "merge_and_score")
