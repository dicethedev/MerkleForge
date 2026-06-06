#!/usr/bin/env python3
"""Generate daily MerkleForge lines-of-code reports."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from github_api import open_repository_counts, repository, server_url


REPORT_PATH = Path("loc_report.json")
OLD_REPORT_PATH = Path("loc_report.json.old")


def run_warloc() -> Any:
    """Run cargo-warloc and return its JSON output."""
    result = subprocess.run(
        ["cargo", "warloc", "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def summarize_warloc(raw: dict[str, Any]) -> dict[str, int]:
    """Aggregate cargo-warloc's main, test, and example statistics."""
    categories = ("main", "tests", "examples")

    def total(field: str) -> int:
        return sum(int(raw.get(category, {}).get(field, 0)) for category in categories)

    code = total("code")
    blank = total("whitespaces")
    docs = total("docs")
    comments = total("comments")
    return {
        "files": int(raw.get("file_count", 0)),
        "code": code,
        "blank": blank,
        "docs": docs,
        "comments": comments,
        "total": code + blank + docs + comments,
    }


def load_previous_total() -> int | None:
    """Read the previous normalized report total, when available."""
    if not OLD_REPORT_PATH.exists():
        return None
    try:
        return int(json.loads(OLD_REPORT_PATH.read_text())["total_lines"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def signed_delta(current: int, previous: int | None) -> str:
    """Format a signed difference or indicate that no baseline exists."""
    if previous is None:
        return "baseline"
    return f"{current - previous:+,}"


def main() -> None:
    """Generate JSON, workflow-summary, and Telegram report files."""
    raw = run_warloc()
    stats = summarize_warloc(raw)
    code = stats["code"]
    blank = stats["blank"]
    docs = stats["docs"]
    comments = stats["comments"]
    files = stats["files"]
    total = stats["total"]
    previous_total = load_previous_total()
    pull_requests, issues = open_repository_counts()
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    report = {
        "repository": repository(),
        "generated_at": generated_at,
        "file_count": files,
        "code_lines": code,
        "blank_lines": blank,
        "doc_comment_lines": docs,
        "comment_lines": comments,
        "total_lines": total,
        "delta_total": None if previous_total is None else total - previous_total,
        "open_pull_requests": pull_requests,
        "open_issues": issues,
        "warloc": raw,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n")

    repo_url = f"{server_url()}/{repository()}"
    delta = signed_delta(total, previous_total)
    summary = f"""## Daily Lines of Code Report

| Metric | Count |
| --- | ---: |
| Rust files | {files:,} |
| Code | {code:,} |
| Documentation comments | {docs:,} |
| Regular comments | {comments:,} |
| Blank lines | {blank:,} |
| Total lines | {total:,} |
| Change since previous report | {delta} |
| Open pull requests | {pull_requests:,} |
| Open issues | {issues:,} |

[View repository]({repo_url})
"""
    Path("loc_report_github.md").write_text(summary)

    telegram = f"""MerkleForge daily report

Rust files: {files:,}
Code: {code:,}
Docs: {docs:,}
Comments: {comments:,}
Total lines: {total:,}
Daily change: {delta}

Open PRs: {pull_requests}
Open issues: {issues}

{repo_url}
"""
    Path("loc_report_telegram.txt").write_text(telegram)


if __name__ == "__main__":
    main()
