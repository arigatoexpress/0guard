#!/usr/bin/env python3
"""Run reviewed reputation connector backfills into derived-only artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from guard0.reputation_backfill import (
    DEFAULT_REPUTATION_BACKFILL_PATH,
    run_phishdestroy_reputation_backfill,
)
from guard0.reputation_connector_worker import PHISHDESTROY_SOURCE_ID


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=PHISHDESTROY_SOURCE_ID)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--subject-url", default="")
    parser.add_argument("--out", default=str(DEFAULT_REPUTATION_BACKFILL_PATH))
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()

    if args.source != PHISHDESTROY_SOURCE_ID:
        parser.error(f"unsupported source: {args.source}")

    payload = run_phishdestroy_reputation_backfill(
        live=args.live,
        limit=args.limit,
        subject_url=args.subject_url,
        out_path=Path(args.out),
        write=not args.no_write,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
