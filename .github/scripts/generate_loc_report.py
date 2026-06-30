#!/usr/bin/env python3
"""Generate weekly MerkleForge lines-of-code reports."""

from __future__ import annotations

import csv
import json
import os
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from github_api import repository, server_url


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


def run_warloc_by_file() -> list[dict[str, str]]:
    """Run cargo-warloc by file and return CSV rows."""
    result = subprocess.run(
        ["cargo", "warloc", "--by-file", "-o", "csv"],
        check=True,
        capture_output=True,
        text=True,
    )
    return list(csv.DictReader(result.stdout.splitlines()))


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


def crate_name_for_path(path: str) -> str:
    """Infer a workspace crate name from a Rust file path."""
    normalized = path.strip().lstrip("./").replace("\\", "/")
    parts = [part for part in normalized.split("/") if part and part != "."]
    if not parts:
        return "unknown"
    if parts[0] in {"merkle-bench", "merkle-core", "merkle-hash", "merkle-variants", "website"}:
        return parts[0]
    if parts[0] in {"src", "tests", "benches", "examples", "bin", "crates"} and len(parts) > 1:
        return parts[1]
    return parts[0]


def summarize_crates(rows: list[dict[str, str]]) -> list[tuple[str, int, int]]:
    """Aggregate no-tests and with-tests totals by crate."""
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        crate = crate_name_for_path(row["File"])
        main_total = sum(
            int(row.get(column, 0))
            for column in ("Main Code", "Main Docs", "Main Comments", "Main Spaces")
        )
        test_total = sum(
            int(row.get(column, 0))
            for column in ("Test Code", "Test Docs", "Test Comments", "Test Spaces")
        )
        totals[crate][0] += main_total
        totals[crate][1] += main_total + test_total

    return sorted((crate, values[0], values[1]) for crate, values in totals.items())


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


def build_weekly_summary(
    date_label: str,
    commit_sha: str,
    repo_url: str,
    crates: list[tuple[str, int] | tuple[str, int, int]],
    no_tests_total: int,
    with_tests_total: int,
) -> str:
    """Build the Markdown summary for the weekly report."""
    lines = [
        "## Weekly MerkleForge LoC Report",
        "",
        f"Date: {date_label} • Commit: {commit_sha}",
        "",
        "**Per-crate (no tests)**",
    ]
    for crate, *values in crates:
        no_tests = values[0] if values else 0
        lines.append(f"**{crate}**: {no_tests}")
    lines.extend(
        [
            "",
            f"**Total Rust LoC (no tests):** {no_tests_total}",
            f"**Total Rust LoC (with tests):** {with_tests_total}",
            "",
            f"[View repository]({repo_url})",
        ]
    )
    return "\n".join(lines) + "\n"


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
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    date_label = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    commit_sha = (
        os.environ.get("GITHUB_SHA", "").strip()[:7]
        or subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    crate_totals = summarize_crates(run_warloc_by_file())
    no_tests_total = sum(no_tests for _, no_tests, _ in crate_totals)
    with_tests_total = sum(with_tests for _, _, with_tests in crate_totals)

    report = {
        "repository": repository(),
        "generated_at": generated_at,
        "date_label": date_label,
        "commit": commit_sha,
        "file_count": files,
        "code_lines": code,
        "blank_lines": blank,
        "doc_comment_lines": docs,
        "comment_lines": comments,
        "total_lines": total,
        "delta_total": None if previous_total is None else total - previous_total,
        "crates": [
            {"name": crate, "no_tests": no_tests, "with_tests": with_tests}
            for crate, no_tests, with_tests in crate_totals
        ],
        "warloc": raw,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n")

    repo_url = f"{server_url()}/{repository()}"
    summary = build_weekly_summary(
        date_label=date_label,
        commit_sha=commit_sha,
        repo_url=repo_url,
        crates=crate_totals,
        no_tests_total=no_tests_total,
        with_tests_total=with_tests_total,
    )
    Path("loc_report_github.md").write_text(summary)

    telegram = f"""MerkleForge weekly report

Date: {date_label}
Commit: {commit_sha}

Per-crate (no tests):
"""
    for crate, no_tests, _ in crate_totals:
        telegram += f"- {crate}: {no_tests}\n"
    telegram += f"\nTotal no tests: {no_tests_total}\nTotal with tests: {with_tests_total}\n\n{repo_url}\n"
    Path("loc_report_telegram.txt").write_text(telegram)


if __name__ == "__main__":
    main()
