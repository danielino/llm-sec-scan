# Benchmarks

A benchmark is a repository at a fixed commit with known vulnerabilities. Running the scanner on it and comparing the output with the expected findings measures recall and catches regressions when lenses, prompts or models change.

Each benchmark is one JSON file described by [`benchmark.schema.json`](benchmark.schema.json). Validate them with `python3 scripts/benchmark.py`.

- Locations are `file:line`, relative to the repository root. An expected finding counts as found when the scanner reports one of its locations or clearly the same root cause.
- Set `embargoed: true` while any expected finding is not publicly fixed. Embargoed benchmarks live in `benchmarks/private/`, which is git-ignored, and are never committed.
- Scan a clean clone at the given commit, so that untracked files such as earlier reports cannot leak the answers.

Scoring is manual for now; a scoring script is on the roadmap.
