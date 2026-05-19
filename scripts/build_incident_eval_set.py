#!/usr/bin/env python3
"""Export the deterministic incident eval set used by the model roadmap."""

from __future__ import annotations

import argparse
import json

from guard0.training_data import DEFAULT_INCIDENT_EVAL_PATH, write_incident_detector_eval_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(DEFAULT_INCIDENT_EVAL_PATH),
        help="JSONL output path",
    )
    args = parser.parse_args()
    manifest = write_incident_detector_eval_jsonl(args.out)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
