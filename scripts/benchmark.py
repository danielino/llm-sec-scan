#!/usr/bin/env python3
"""Validate benchmark files against the format in benchmarks/benchmark.schema.json."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = ROOT / "benchmarks"
SCHEMA = BENCHMARKS / "benchmark.schema.json"
SEVERITIES = ("critical", "high", "medium", "low")
TOP_LEVEL = ("name", "repo", "commit", "embargoed", "expected")
EXPECTED = ("id", "title", "bug_class", "severity", "locations")


def validate(data, private):
    """Return the list of problems in one benchmark; empty when valid."""
    if not isinstance(data, dict):
        return ["benchmark must be a JSON object"]
    errors = [f"missing '{key}'" for key in TOP_LEVEL if key not in data]
    if errors:
        return errors
    if not isinstance(data["embargoed"], bool):
        errors.append("'embargoed' must be a boolean")
    elif data["embargoed"] and not private:
        errors.append("embargoed benchmarks must live in benchmarks/private/")
    if not isinstance(data["expected"], list) or not data["expected"]:
        return errors + ["'expected' must be a non-empty list"]
    ids = set()
    for index, item in enumerate(data["expected"]):
        where = f"expected[{index}]"
        missing = [key for key in EXPECTED if key not in item]
        if missing:
            errors.append(f"{where}: missing {missing}")
            continue
        if item["id"] in ids:
            errors.append(f"{where}: duplicate id '{item['id']}'")
        ids.add(item["id"])
        if item["severity"] not in SEVERITIES:
            errors.append(f"{where}: severity must be one of {SEVERITIES}")
        locations = item["locations"]
        if not isinstance(locations, list) or not locations or not all(isinstance(l, str) and ":" in l for l in locations):
            errors.append(f"{where}: locations must be a non-empty list of 'file:line' strings")
    return errors


def benchmark_files():
    files = [p for p in sorted(BENCHMARKS.glob("*.json")) if p != SCHEMA]
    return files + sorted((BENCHMARKS / "private").glob("*.json"))


def main():
    failed = False
    for path in benchmark_files():
        errors = validate(json.loads(path.read_text(encoding="utf-8")), private=path.parent.name == "private")
        for error in errors:
            print(f"{path.relative_to(ROOT)}: {error}", file=sys.stderr)
        failed = failed or bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
