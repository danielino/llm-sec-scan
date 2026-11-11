# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Lenses: `authz-consistency`, `secondary-resources`, `input-to-sink`, `state-and-limits` (per surface), `parser-differential`, `privilege-escalation` (repository-wide).
- Stage prompts (recon, surface and repository lens frames, root-cause dedup, verification with refute, reachability and impact stances, variant hunt) and JSON Schemas for structured output.
- `security-scan` Claude Code workflow generated from `core/` by `scripts/build.py`, with root-cause dedup, majority-vote verification and variant hunt.
- `security-scan` skill and Markdown report renderer, packaged as the `llm-sec-scan` plugin; the repository is its own plugin marketplace.
- Benchmark format and validator; `benchmarks/private/` for embargoed benchmarks.
- Test suite: core validation, reproducible build, workflow smoke tests with mocked agents, report rendering, benchmark validation.
