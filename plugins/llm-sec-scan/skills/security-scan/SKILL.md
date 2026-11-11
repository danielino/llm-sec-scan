---
name: security-scan
description: Run an LLM security audit of one or more local repositories with the llm-sec-scan workflow (recon, lens fan-out, adversarial verification, variant hunt) and render the report. Use when the user asks for a security scan, a vulnerability audit or a pentest-style code review of repositories.
---

# Security scan

1. **Collect the targets**: absolute paths of the repositories to scan. If the user gives URLs, clone them.
2. **Scan clean clones.** Clone each target into the session scratchpad (`git clone <path-or-url> <scratchpad>/scan/<name>`) and scan the clone, so untracked files such as earlier audit reports or local secrets never reach the agents. Record the commit with `git -C <clone> rev-parse --short HEAD`.
3. **State the cost before starting.** Per repository, with the defaults, expect about `maxSurfaces x 4 + 2` scan agents plus `verifyVotes` agents per verified cluster: often 40 to 100 agents and several million tokens. Unless the user already asked for this scale, confirm first and offer `maxSurfaces`, `verifyVotes` or `lenses` to reduce it.
4. **Run the workflow** `llm-sec-scan:security-scan` with the Workflow tool (`name`), passing `args` as a JSON object, not as a string, for example `{"repos": ["/abs/path/one", "/abs/path/two"], "maxSurfaces": 8, "maxClusters": 30, "verifyVotes": 2}`.
5. **Render the report** when the workflow completes. Its full output is in the task output file; the renderer accepts both that wrapper and the raw result:
   `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/render_report.py <task-output-file> --date <YYYY-MM-DD> -o <scratchpad>/security-report.md`
6. **Report to the user**, per repository: coverage first (surfaces not scanned, clusters left unverified), then findings by severity with their verdict. Say plainly that verification is static (no proof of concept was executed) and that PLAUSIBLE findings need manual confirmation.

## Handling results

Findings are undisclosed vulnerabilities. Do not commit reports into the scanned repositories, do not publish them and do not open public issues; for third-party code, follow coordinated disclosure.
