#!/usr/bin/env python3
"""Validate core/ and bundle it into the Claude Code workflow.

The workflow runtime has no filesystem access, so lenses, prompts, stances and
schemas are embedded into the generated script at build time.
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "core"
TEMPLATE = ROOT / "src" / "workflow.template.js"
PLUGIN = ROOT / "plugins" / "llm-sec-scan"
OUTPUT = PLUGIN / "workflows" / "security-scan.js"

MARKER = "/*@@BUNDLE@@*/ null"
PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")
SCOPES = ("surface", "repo")
LENS_KEYS = ("id", "title", "scope", "bug_classes")
SCHEMA_NAMES = ("recon", "findings", "clusters", "verdict")
STANCE_ORDER = ("refute", "reachability", "impact")
# Placeholders each prompt must use; src/workflow.template.js fills exactly these.
PROMPT_VARS = {
    "rules": (),
    "recon": ("repo", "max_surfaces", "rules"),
    "surface-lens": ("context", "surface", "lens", "rules"),
    "repo-lens": ("context", "system_model", "lens", "rules"),
    "dedup": ("findings",),
    "verify": ("stance", "context", "finding", "rules"),
    "variants": ("context", "confirmed", "known", "rules"),
}


class BuildError(Exception):
    """Invalid content in core/ or src/."""


def parse_front_matter(text, name):
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        raise BuildError(f"{name}: missing front matter")
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        raise BuildError(f"{name}: unterminated front matter")
    meta = {}
    for line in lines[1:end]:
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise BuildError(f"{name}: malformed front matter line {line!r}")
        meta[key.strip()] = value.strip()
    return meta, "\n".join(lines[end + 1:]).strip()


def check_placeholders(name, text, expected):
    found = set(PLACEHOLDER.findall(text))
    missing = sorted(set(expected) - found)
    unknown = sorted(found - set(expected))
    if missing or unknown:
        raise BuildError(f"{name}: missing placeholders {missing}, unknown placeholders {unknown}")


def load_lenses():
    lenses = []
    for path in sorted((CORE / "lenses").glob("*.md")):
        meta, body = parse_front_matter(path.read_text(encoding="utf-8"), path.name)
        for key in LENS_KEYS:
            if not meta.get(key):
                raise BuildError(f"{path.name}: missing '{key}'")
        if meta["id"] != path.stem:
            raise BuildError(f"{path.name}: id '{meta['id']}' must match the file name")
        if meta["scope"] not in SCOPES:
            raise BuildError(f"{path.name}: scope must be one of {SCOPES}")
        if not body:
            raise BuildError(f"{path.name}: empty body")
        check_placeholders(path.name, body, ())
        lenses.append({
            "id": meta["id"],
            "title": meta["title"],
            "scope": meta["scope"],
            "bug_classes": [c.strip() for c in meta["bug_classes"].split(",") if c.strip()],
            "body": body,
        })
    if not lenses:
        raise BuildError("core/lenses: no lenses")
    return lenses


def load_prompts():
    directory = CORE / "prompts"
    extra = sorted({p.stem for p in directory.glob("*.md")} - set(PROMPT_VARS))
    if extra:
        raise BuildError(f"core/prompts: undeclared prompts {extra}; add them to PROMPT_VARS")
    prompts = {}
    for name, expected in PROMPT_VARS.items():
        path = directory / f"{name}.md"
        if not path.is_file():
            raise BuildError(f"core/prompts: missing {path.name}")
        text = path.read_text(encoding="utf-8").strip()
        check_placeholders(path.name, text, expected)
        prompts[name] = text
    return prompts


def load_stances():
    directory = CORE / "prompts" / "stances"
    found = {p.stem for p in directory.glob("*.md")}
    if found != set(STANCE_ORDER):
        raise BuildError(f"core/prompts/stances: expected {sorted(STANCE_ORDER)}, found {sorted(found)}")
    stances = []
    for name in STANCE_ORDER:
        text = (directory / f"{name}.md").read_text(encoding="utf-8").strip()
        check_placeholders(f"stances/{name}.md", text, ())
        stances.append({"id": name, "text": text})
    return stances


def check_schema(node, where):
    if isinstance(node, dict):
        if node.get("type") == "object":
            undeclared = sorted(set(node.get("required", ())) - set(node.get("properties", {})))
            if undeclared:
                raise BuildError(f"{where}: required but not in properties: {undeclared}")
        for key, value in node.items():
            check_schema(value, f"{where}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            check_schema(value, f"{where}[{index}]")


def load_schemas():
    schemas = {}
    for name in SCHEMA_NAMES:
        path = CORE / "schemas" / f"{name}.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        if schema.get("type") != "object" or "properties" not in schema:
            raise BuildError(f"{path.name}: root must be an object schema with properties")
        check_schema(schema, name)
        schemas[name] = schema
    return schemas


def load_version():
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    return manifest["version"]


def inject(template, bundle):
    if template.count(MARKER) != 1:
        raise BuildError(f"template must contain the marker {MARKER!r} exactly once")
    payload = json.dumps(bundle, indent=1, sort_keys=True, ensure_ascii=False)
    return template.replace(MARKER, payload)


def render():
    bundle = {
        "VERSION": load_version(),
        "LENSES": load_lenses(),
        "PROMPTS": load_prompts(),
        "STANCES": load_stances(),
        "SCHEMAS": load_schemas(),
    }
    return inject(TEMPLATE.read_text(encoding="utf-8"), bundle)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the generated workflow is stale")
    args = parser.parse_args()
    try:
        output = render()
    except BuildError as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else None
        if current != output:
            print(f"{OUTPUT.relative_to(ROOT)} is stale: run python3 scripts/build.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(output, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
