#!/usr/bin/env python3
"""Render a security-scan workflow result (JSON) as a Markdown report."""

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VERDICT_ORDER = {"CONFIRMED": 0, "PLAUSIBLE": 1}


def load_result(data):
    """Return the workflow result from either the raw value or the task output wrapper."""
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data
    inner = data.get("result") if isinstance(data, dict) else None
    if isinstance(inner, dict) and isinstance(inner.get("results"), list):
        return inner
    raise ValueError("not a security-scan result: expected a 'results' list")


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def sort_key(finding):
    verdict = finding["verdict"]
    return (
        SEVERITY_ORDER.get(verdict["severity"], len(SEVERITY_ORDER)),
        VERDICT_ORDER.get(verdict["verdict"], len(VERDICT_ORDER)),
    )


def first_vote_field(votes, field):
    for vote in votes:
        if vote.get("verdict") != "REFUTED" and vote.get(field):
            return vote[field]
    return ""


def render_finding(number, finding):
    verdict = finding["verdict"]
    origin = " · from variant hunt" if finding.get("from_variant_hunt") else ""
    out = [
        f"#### {number}. {finding['title']}",
        "",
        f"- **Severity:** {verdict['severity']} · **Verdict:** {verdict['verdict']}{origin}",
        f"- **Location:** `{finding['file']}:{finding['line']}`",
    ]
    if finding.get("other_locations"):
        out.append("- **Also at:** " + ", ".join(f"`{loc}`" for loc in finding["other_locations"]))
    out += [
        f"- **Class:** {finding['bug_class']}",
        f"- **Attacker:** {finding['attacker']}",
        "",
        f"**Root cause.** {finding['root_cause']}",
        "",
        f"**Exploit.** {finding['exploit']}",
        "",
        f"**Impact.** {finding['impact']}",
        "",
    ]
    votes = verdict.get("votes", [])
    poc = first_vote_field(votes, "poc")
    if poc:
        out += ["**Proof of concept.**", "", "```", poc, "```", ""]
    test = first_vote_field(votes, "regression_test")
    if test:
        out += [f"**Regression test.** {test}", ""]
    if votes:
        out += ["**Votes.**", ""]
        out += [f"- {v.get('stance', '?')}: {v['verdict']} ({v.get('severity', '?')}). {v.get('reasoning', '')}" for v in votes]
        out.append("")
    return out


def render_repo(repo):
    if repo is None:
        return ["## Unknown repository", "", "Scan failed: the workflow returned no result for this repository.", ""]
    out = [f"## {repo['repo']}", ""]
    if repo.get("error"):
        return out + [f"Scan failed: {repo['error']}", ""]
    coverage, stats = repo["coverage"], repo["stats"]
    out += [
        repo.get("summary", ""),
        "",
        "### Coverage",
        "",
        f"- Surfaces scanned: {len(coverage['surfaces_scanned'])} of {coverage['surfaces_total']}",
    ]
    if coverage["surfaces_not_scanned"]:
        out.append(f"- Not scanned: {', '.join(coverage['surfaces_not_scanned'])}")
    out += [
        f"- Lenses: {', '.join(coverage['lenses'])}",
        f"- Verifier votes per cluster: {coverage['verify_votes']}",
        f"- Findings: {stats['raw']} raw, {stats['clusters']} clusters, {stats['verified']} verified, "
        f"{stats['refuted']} refuted, {stats['unverified']} unverified, {stats['variants']} from variant hunt, "
        f"{stats['final']} reported",
        "",
        "### Findings",
        "",
    ]
    findings = sorted(repo["findings"], key=sort_key)
    if not findings:
        out += ["None.", ""]
    else:
        out += ["| # | Severity | Verdict | Title | Location |", "|---|---|---|---|---|"]
        for number, f in enumerate(findings, 1):
            out.append(
                f"| {number} | {f['verdict']['severity']} | {f['verdict']['verdict']} | "
                f"{cell(f['title'])} | `{cell(f['file'])}:{f['line']}` |"
            )
        out.append("")
        for number, f in enumerate(findings, 1):
            out += render_finding(number, f)
    if repo.get("refuted"):
        out += ["### Refuted", ""]
        out += [f"- {r['title']} (`{r['file']}:{r['line']}`)" for r in repo["refuted"]]
        out.append("")
    if repo.get("unverified"):
        out += ["### Unverified", "", "Low severity or over the verification cap: no verifier checked these.", ""]
        out += [f"- [{u['severity']}] {u['title']} (`{u['file']}:{u['line']}`)" for u in repo["unverified"]]
        out.append("")
    return out


def render(result, title="Security scan report", date=None):
    header = f"llm-sec-scan {result.get('version', 'unknown')}" + (f" · {date}" if date else "")
    out = [f"# {title}", "", header, ""]
    for repo in result["results"]:
        out += render_repo(repo)
    return "\n".join(out).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="workflow result or task output file (JSON)")
    parser.add_argument("-o", "--output", type=Path, help="write the report here instead of stdout")
    parser.add_argument("--title", default="Security scan report")
    parser.add_argument("--date", help="date shown in the report header")
    args = parser.parse_args()
    try:
        result = load_result(json.loads(args.input.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        print(f"render_report: {error}", file=sys.stderr)
        return 1
    report = render(result, args.title, args.date)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
