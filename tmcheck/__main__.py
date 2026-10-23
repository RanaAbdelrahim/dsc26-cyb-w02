"""Command line: python -m tmcheck MODEL.yaml

Print one JSON object with the keys "issues", "gaps", "policy" and "ranked" (each a list of
objects with the dataclass fields, for example {"ref": "f01", "category": "T"}).
Exit code 2 if the file cannot be loaded, 1 if there are any issues, gaps or policy findings,
otherwise 0. If there are structural issues you may leave "gaps" and "policy" empty.
"""
import sys
import json
from dataclasses import asdict

from tmcheck.core import (
    ModelError,
    load_model,
    validate,
    coverage_gaps,
    policy_findings,
    rank,
    )


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    path = argv[0]


    try:
        model = load_model(path)
    except ModelError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    issues = validate(model)

    if issues:
        gaps = []
        policy = []
    else:
        gaps = coverage_gaps(model)
        policy = policy_findings(model)

    ranked = rank(model)

    result = {
        "issues": [asdict(item) for item in issues],
        "gaps": [asdict(item) for item in gaps],
        "policy": [asdict(item) for item in policy],
        "ranked": [asdict(item) for item in ranked],
    }

    print(json.dumps(result, indent=2))

    if issues or gaps or policy:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
