from __future__ import annotations

import argparse
import shutil
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove expired evidence directories.")
    parser.add_argument("--output", default="/output")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.days < 0:
        raise SystemExit("--days must be non-negative")
    threshold = time.time() - args.days * 86400
    root = Path(args.output)
    removed = 0
    for task_dir in root.iterdir() if root.exists() else []:
        evidence = task_dir / "evidence"
        if not evidence.is_dir():
            continue
        newest = max(
            (item.stat().st_mtime for item in evidence.iterdir()),
            default=evidence.stat().st_mtime,
        )
        if newest >= threshold:
            continue
        removed += 1
        print(("DRY-RUN " if args.dry_run else "") + str(evidence))
        if not args.dry_run:
            shutil.rmtree(evidence)
    print(f"expired_evidence_sets={removed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
