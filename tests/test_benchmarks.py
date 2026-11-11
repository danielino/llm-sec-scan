"""Benchmark files and the benchmark validator."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import benchmark  # noqa: E402


def valid():
    return {"name": "toy", "repo": "https://example.invalid/toy.git", "commit": "abc1234", "embargoed": False,
            "expected": [{"id": "B1", "title": "t", "bug_class": "IDOR", "severity": "high", "locations": ["src/a.rs:10"]}]}


class BenchmarkTests(unittest.TestCase):
    def test_existing_benchmark_files_are_valid(self):
        for path in benchmark.benchmark_files():
            with self.subTest(path=path.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(benchmark.validate(data, private=path.parent.name == "private"), [])

    def test_valid_benchmark_passes(self):
        self.assertEqual(benchmark.validate(valid(), private=False), [])

    def test_embargoed_benchmark_must_be_private(self):
        data = valid()
        data["embargoed"] = True
        self.assertTrue(benchmark.validate(data, private=False))
        self.assertEqual(benchmark.validate(data, private=True), [])

    def test_invalid_entries_are_reported(self):
        data = valid()
        data["expected"].append(dict(data["expected"][0], severity="urgent", locations=["no-line"]))
        errors = benchmark.validate(data, private=False)
        self.assertTrue(any("duplicate id" in e for e in errors))
        self.assertTrue(any("severity" in e for e in errors))
        self.assertTrue(any("locations" in e for e in errors))

    def test_missing_top_level_keys_are_reported(self):
        self.assertEqual(benchmark.validate({"name": "x"}, private=False),
                         ["missing 'repo'", "missing 'commit'", "missing 'embargoed'", "missing 'expected'"])

    def test_schema_matches_the_validator(self):
        schema = json.loads(benchmark.SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["required"], list(benchmark.TOP_LEVEL))
        self.assertEqual(schema["properties"]["expected"]["items"]["required"], list(benchmark.EXPECTED))


if __name__ == "__main__":
    unittest.main()
