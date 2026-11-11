"""Runs the generated workflow end to end with mocked agents (tests/harness/run_workflow.cjs)."""

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build  # noqa: E402

HARNESS = ROOT / "tests" / "harness" / "run_workflow.cjs"
NODE = shutil.which("node")


def run_scenario(name):
    if NODE is None:
        raise RuntimeError("node is required for the workflow smoke tests")
    proc = subprocess.run([NODE, str(HARNESS), str(build.OUTPUT), name],
                          capture_output=True, text=True, timeout=60)
    return proc, json.loads(proc.stdout)


class WorkflowSmokeTests(unittest.TestCase):
    def assert_clean(self, proc, data):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("fatal", data)
        self.assertEqual(data["errors"], [])

    def test_default_pipeline(self):
        proc, data = run_scenario("default")
        self.assert_clean(proc, data)
        result = data["result"]
        self.assertEqual(result["version"], build.load_version())
        repo = result["results"][0]
        self.assertEqual(repo["stats"], {"raw": 3, "clusters": 2, "verified": 1, "refuted": 0,
                                         "unverified": 1, "variants": 0, "final": 1})
        finding = repo["findings"][0]
        self.assertEqual(finding["title"], "Auth uses original URI")
        self.assertEqual(finding["verdict"]["verdict"], "CONFIRMED")
        self.assertEqual(finding["verdict"]["severity"], "high")
        self.assertEqual(finding["members"], 2)
        self.assertEqual(finding["other_locations"], ["src/auth.rs:12"])
        self.assertEqual(finding["lenses"], ["authz-consistency", "parser-differential"])
        self.assertEqual(repo["coverage"]["surfaces_not_scanned"], ["CLI"])
        self.assertEqual(repo["unverified"][0]["title"], "Unbounded list")
        self.assertTrue(any("not scanned: CLI" in m for m in data["logs"]))
        # recon, 4 surface lenses x 1 surface, 2 repo lenses, dedup, 2 votes, variants, 2 votes on the variant
        self.assertEqual(len(data["calls"]), 13)

    def test_invalid_dedup_falls_back_to_location_keys(self):
        proc, data = run_scenario("dedup-invalid")
        self.assert_clean(proc, data)
        repo = data["result"]["results"][0]
        self.assertEqual(repo["stats"]["clusters"], 2)
        self.assertEqual(repo["findings"][0]["members"], 2)
        self.assertTrue(any("falling back" in m for m in data["logs"]))

    def test_split_vote_is_plausible_with_the_standing_severity(self):
        proc, data = run_scenario("split")
        self.assert_clean(proc, data)
        finding = data["result"]["results"][0]["findings"][0]
        self.assertEqual(finding["verdict"]["verdict"], "PLAUSIBLE")
        self.assertEqual(finding["verdict"]["severity"], "critical")
        self.assertEqual([v["stance"] for v in finding["verdict"]["votes"]], ["refute", "reachability"])


if __name__ == "__main__":
    unittest.main()
