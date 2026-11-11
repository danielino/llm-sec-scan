"""Validation of core/: lenses, prompts, stances and schemas."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build  # noqa: E402


class LensTests(unittest.TestCase):
    def test_lenses_load_with_unique_ids_and_both_scopes(self):
        lenses = build.load_lenses()
        ids = [lens["id"] for lens in lenses]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual({lens["scope"] for lens in lenses}, set(build.SCOPES))
        for lens in lenses:
            self.assertTrue(lens["bug_classes"], lens["id"])

    def test_front_matter_parses_keys_and_body(self):
        meta, body = build.parse_front_matter("---\nid: x\nscope: repo\n---\n\nQuestions.\n", "x.md")
        self.assertEqual(meta, {"id": "x", "scope": "repo"})
        self.assertEqual(body, "Questions.")

    def test_front_matter_must_be_terminated(self):
        with self.assertRaises(build.BuildError):
            build.parse_front_matter("---\nid: x\nbody", "x.md")

    def test_front_matter_is_required(self):
        with self.assertRaises(build.BuildError):
            build.parse_front_matter("just a body", "x.md")


class PromptTests(unittest.TestCase):
    def test_prompts_use_exactly_the_declared_placeholders(self):
        self.assertEqual(set(build.load_prompts()), set(build.PROMPT_VARS))

    def test_check_placeholders_rejects_unknown_and_missing(self):
        with self.assertRaises(build.BuildError):
            build.check_placeholders("p", "{{a}} {{b}}", ("a",))
        with self.assertRaises(build.BuildError):
            build.check_placeholders("p", "{{a}}", ("a", "b"))
        build.check_placeholders("p", "{{a}} and {{a}} again", ("a",))

    def test_stances_follow_the_declared_order(self):
        self.assertEqual([s["id"] for s in build.load_stances()], list(build.STANCE_ORDER))


class SchemaTests(unittest.TestCase):
    def test_schemas_load(self):
        self.assertEqual(set(build.load_schemas()), set(build.SCHEMA_NAMES))

    def test_required_fields_must_be_declared(self):
        with self.assertRaises(build.BuildError):
            build.check_schema({"type": "object", "properties": {"a": {}}, "required": ["a", "b"]}, "top")

    def test_nested_required_fields_are_checked(self):
        nested = {"type": "object", "properties": {"items": {"type": "array", "items": {
            "type": "object", "properties": {}, "required": ["x"]}}}}
        with self.assertRaises(build.BuildError):
            build.check_schema(nested, "nested")


if __name__ == "__main__":
    unittest.main()
