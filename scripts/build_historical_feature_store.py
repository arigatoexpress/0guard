#!/usr/bin/env python3
"""Export the ZeroGuard seed historical feature store as JSONL."""

from __future__ import annotations

import argparse
import json

from guard0.historical_feature_store import (
    DEFAULT_HISTORICAL_FEATURE_STORE_PATH,
    write_historical_feature_store_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(DEFAULT_HISTORICAL_FEATURE_STORE_PATH),
        help="JSONL output path",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional incident-row limit; reputation summary still appends unless disabled.",
    )
    parser.add_argument(
        "--no-reputation",
        action="store_true",
        help="Exclude the local reputation backfill summary row.",
    )
    args = parser.parse_args()
    manifest = write_historical_feature_store_jsonl(
        args.out,
        limit=args.limit,
        include_reputation=not args.no_reputation,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
