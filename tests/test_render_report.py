"""Markdown rendering of workflow results."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plugins" / "llm-sec-scan" / "scripts"))

import render_report  # noqa: E402


def finding(title, severity, verdict, line):
    return {
        "title": title, "bug_class": "authorization bypass", "severity": severity,
        "file": "src/auth.rs", "line": line, "other_locations": ["src/api.rs:5"],
        "attacker": "low-privilege user", "root_cause": "cause", "exploit": "GET /x",
        "impact": "read data", "confidence": 0.9, "members": 1, "lenses": ["authz-consistency"],
        "verdict": {"verdict": verdict, "severity": severity, "votes": [{
            "stance": "refute", "verdict": verdict, "severity": severity, "reasoning": "checked",
            "poc": "curl -X GET /x", "regression_test": "deny GET /x"}]},
    }


def sample():
    return {"version": "0.1.0", "results": [
        {
            "repo": "/work/toy", "summary": "Toy service.",
            "coverage": {"surfaces_total": 3, "surfaces_scanned": ["API", "Admin"], "surfaces_not_scanned": ["CLI"],
                         "lenses": ["authz-consistency"], "verify_votes": 2},
            "stats": {"raw": 5, "clusters": 4, "verified": 3, "refuted": 1, "unverified": 1, "variants": 0, "final": 2},
            "findings": [finding("Medium | issue", "medium", "PLAUSIBLE", 30),
                         finding("Critical issue", "critical", "CONFIRMED", 10)],
            "refuted": [{"title": "False alarm", "file": "src/x.rs", "line": 1, "votes": []}],
            "unverified": [{"title": "Minor", "severity": "low", "file": "src/y.rs", "line": 2, "lens": "state-and-limits"}],
        },
        {"repo": "/work/broken", "error": "recon failed"},
        None,
    ]}


class RenderReportTests(unittest.TestCase):
    def test_findings_are_ordered_by_severity(self):
        report = render_report.render(sample())
        self.assertLess(report.index("| 1 | critical | CONFIRMED"), report.index("| 2 | medium | PLAUSIBLE"))

    def test_table_cells_escape_pipes(self):
        self.assertIn("Medium \\| issue", render_report.render(sample()))

    def test_details_include_proof_of_concept_and_locations(self):
        report = render_report.render(sample())
        self.assertIn("curl -X GET /x", report)
        self.assertIn("`src/api.rs:5`", report)
        self.assertIn("Not scanned: CLI", report)

    def test_refuted_unverified_and_failed_repositories_are_listed(self):
        report = render_report.render(sample())
        self.assertIn("False alarm", report)
        self.assertIn("[low] Minor", report)
        self.assertIn("Scan failed: recon failed", report)
        self.assertIn("## Unknown repository", report)

    def test_header_carries_version_and_date(self):
        self.assertIn("llm-sec-scan 0.1.0 · 2026-11-11", render_report.render(sample(), date="2026-11-11"))

    def test_task_output_wrapper_is_accepted(self):
        wrapped = {"summary": "x", "result": sample()}
        self.assertEqual(render_report.load_result(wrapped), sample())

    def test_other_json_is_rejected(self):
        with self.assertRaises(ValueError):
            render_report.load_result({"foo": 1})


if __name__ == "__main__":
    unittest.main()
