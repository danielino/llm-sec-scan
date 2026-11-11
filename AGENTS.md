# AGENTS.md

Guidance for coding agents (Claude Code and any other AGENTS.md-aware tool) working in this repository.

## Project

llm-sec-scan is an LLM-driven security scanner for source repositories. It decomposes an audit into closed questions anchored to a model of the system: recon, surface x lens fan-out, root-cause dedup, multi-vote adversarial verification, variant hunt. It ships as a Claude Code plugin (a dynamic workflow plus a skill) distributed through this repository, which is also its own plugin marketplace.

## Layout

| Path | Contents |
|---|---|
| `core/lenses/` | One Markdown file per lens: front matter (`id`, `title`, `scope`, `bug_classes`) and the closed questions |
| `core/prompts/` | Stage prompts with `{{placeholders}}`; `stances/` holds the verifier stances |
| `core/schemas/` | JSON Schemas for structured agent output |
| `src/workflow.template.js` | Orchestration only, no prompt text |
| `plugins/llm-sec-scan/` | The installable plugin: manifest, skill, generated workflow, report renderer |
| `scripts/build.py` | Validates `core/` and bundles it into the workflow |
| `scripts/benchmark.py` | Validates benchmark files |
| `benchmarks/` | Benchmark format; `benchmarks/private/` is git-ignored |
| `tests/` | stdlib `unittest` suite, plus a Node harness that runs the workflow with mocked agents |

## Rules

- **`core/` is the source of truth.** Never edit `plugins/llm-sec-scan/workflows/security-scan.js` by hand: change `core/` or `src/`, run `python3 scripts/build.py`, and commit both. The tests fail when the generated file is stale.
- **Prompt placeholders are a contract.** The `{{variables}}` each prompt must use are declared in `PROMPT_VARS` in `scripts/build.py` and filled in `src/workflow.template.js`: change the three together. Lens and stance bodies take no placeholders.
- **The workflow script runs in a sandbox**: plain JavaScript, no filesystem or Node APIs, no `Date.now()`, `Math.random()` or argless `new Date()`. `export const meta` must stay the first statement and a pure literal.
- **No third-party dependencies** for scripts and tests: Python standard library (3.10+) and Node (22+) only.
- **Everything committed is in English.**
- **Never commit vulnerability details about third-party or unreleased code.** Benchmarks of embargoed findings live in `benchmarks/private/`; scan outputs stay out of git.

## Build and test

```bash
python3 scripts/build.py           # regenerate the workflow from core/ and src/
python3 scripts/build.py --check   # fail if the generated workflow is stale
python3 scripts/benchmark.py       # validate benchmark files
python3 -m unittest discover -s tests -v
```

Run the full suite after every change; every change ships with tests, and all tests pass before committing. CI (`.github/workflows/ci.yml`) runs the same checks on Python 3.10 and 3.13 with Node 22 for every push to `main`/`develop` and every pull request.

## Adding or changing a lens

1. Add `core/lenses/<id>.md`; `id` must equal the file name. `scope: surface` runs once per scanned surface, `scope: repo` runs once per repository with the full system model.
2. Phrase it as closed questions the agent must answer, not as "find bugs".
3. Rebuild, run the tests and, when possible, compare a benchmark before and after.

Every surface lens multiplies the agent count by the number of scanned surfaces: keep the set small and sharp.

## Versioning

SemVer, Conventional Commits, gitflow (`feature/*` into `develop`, releases into `main`, tagged `vX.Y.Z`). The version lives in `plugins/llm-sec-scan/.claude-plugin/plugin.json`, and the build embeds it in the workflow. Record changes in `CHANGELOG.md` (Keep a Changelog).
