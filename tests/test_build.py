"""Generation of the workflow from src/ and core/."""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build  # noqa: E402


class BuildTests(unittest.TestCase):
    def test_render_is_deterministic(self):
        self.assertEqual(build.render(), build.render())

    def test_generated_workflow_is_up_to_date(self):
        self.assertEqual(
            build.OUTPUT.read_text(encoding="utf-8"), build.render(),
            "generated workflow is stale: run python3 scripts/build.py",
        )

    def test_check_mode_passes_on_fresh_output(self):
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "build.py"), "--check"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_meta_stays_the_first_statement(self):
        self.assertTrue(build.render().startswith("export const meta = {"))

    def test_bundle_is_injected_with_the_plugin_version(self):
        output = build.render()
        self.assertNotIn("@@BUNDLE@@", output)
        self.assertIn(f'"VERSION": "{build.load_version()}"', output)

    def test_inject_requires_exactly_one_marker(self):
        with self.assertRaises(build.BuildError):
            build.inject("const BUNDLE = null", {})
        with self.assertRaises(build.BuildError):
            build.inject(build.MARKER + build.MARKER, {})


if __name__ == "__main__":
    unittest.main()
