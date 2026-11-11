# llm-sec-scan

LLM-driven security scanning for source repositories, packaged as a Claude Code plugin.

Generic "find vulnerabilities in this repo" prompts are good at local, pattern-shaped bugs (injection, unsafe calls, leaked secrets) and poor at the bugs that matter most in mature code: logic flaws that live *between* components, such as an authorization layer and a handler that interpret the same request differently, or a handler that touches a resource nobody authorized. llm-sec-scan targets those by turning an audit into many small, closed questions anchored to a model of the system, and by separating the agents that propose findings from the agents that try to refute them.

## How it works

```
Recon      one agent per repository builds a system model: actors, assets, attack
           surfaces with their ordered layer chain and decision points, parser pairs
Scan       surface x lens: one agent per (surface, lens) answers that lens's closed
           questions along the surface's full layer chain; repository-wide lenses run once
Dedup      findings are clustered by root cause (one fix = one cluster)
Verify     every cluster of severity medium or higher gets N independent verifiers,
           each with a different stance (refute, trace reachability, assess impact);
           a majority vote decides CONFIRMED / PLAUSIBLE / REFUTED
Variants   surviving root causes are hunted across the whole repository; new
           instances go through the same verification
```

Lenses shipped today:

| Lens | Scope | Looks for |
|---|---|---|
| `authz-consistency` | surface | authorization computed on a different request representation, action or resource than the one executed |
| `secondary-resources` | surface | resources read or written beyond the one authorized (IDOR, confused deputy), existence oracles |
| `input-to-sink` | surface | untrusted input reaching filesystem, SQL, shell, deserializers, outbound requests, logs, HTML |
| `state-and-limits` | surface | TOCTOU, races, unbounded resource use, replay, cryptographic misuse |
| `parser-differential` | repository | two components interpreting the same input differently across a security decision |
| `privilege-escalation` | repository | permissions that transitively grant more than they say (self-granting, credential minting) |

## Install

The repository is its own plugin marketplace. In Claude Code:

```
/plugin marketplace add danielino/llm-sec-scan
/plugin install llm-sec-scan@llm-sec-scan
```

The repository is private: Claude Code clones it with your existing git credentials.

## Usage

Ask Claude Code for a security scan of one or more repositories (the `security-scan` skill guides it), or run the `llm-sec-scan:security-scan` workflow directly with these arguments:

| Argument | Default | Meaning |
|---|---|---|
| `repos` | required | absolute paths of the repositories to scan |
| `maxSurfaces` | 8 | surfaces scanned per repository, highest risk first; the rest are reported as not scanned |
| `maxClusters` | 30 | verification cap per repository; clusters over the cap are reported as unverified |
| `verifyVotes` | 2 | independent verifiers per cluster (1 to 3) |
| `findModel` | `sonnet` | model for the surface finders and the dedup step; recon, repository-wide lenses, verification and the variant hunt use the session model |
| `lenses` | all | subset of lens ids to run |

Scan a **clean clone**, not your working copy: untracked files such as earlier audit reports would otherwise leak into the analysis. The result is JSON; render it with:

```bash
python3 plugins/llm-sec-scan/scripts/render_report.py result.json --date 2026-11-11 -o report.md
```

### Cost

A scan is expensive. On a mid-sized Rust server the first prototype used 47 agents, about 3.3M tokens and 28 minutes, with 6 surfaces, 4 surface lenses and single-vote verification. Agent count grows roughly with `maxSurfaces x surface lenses + clusters x verifyVotes`.

## Benchmarks

`benchmarks/` defines a format for repositories with known vulnerabilities, used to measure recall and to catch regressions when lenses, prompts or models change. Benchmarks whose findings are not yet publicly fixed go in `benchmarks/private/`, which is git-ignored.

## Responsible use

Findings are undisclosed vulnerabilities. Scan only code you are authorized to assess, keep results out of public places, and follow coordinated disclosure for third-party projects.

## Development

See [AGENTS.md](AGENTS.md).

## Roadmap

- Benchmark scoring script (recall and precision against expected findings)
- Dynamic verification: build and run the target in a sandbox and execute the proof of concept
- Incremental scans on a diff, reusing the cached system model
- SARIF output for code-scanning integrations
