#!/usr/bin/env python3
"""Build Telegram messages for GitHub repository events."""

from __future__ import annotations

import json
import os
import urllib.error
from pathlib import Path
from typing import Any

from github_api import open_repository_counts, repository, server_url


def event_payload() -> dict[str, Any]:
    """Load the current GitHub Actions event payload."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    return json.loads(Path(path).read_text())


def actor_name(payload: dict[str, Any]) -> str:
    """Return the event actor login."""
    return payload.get("sender", {}).get("login", "unknown")


def repository_count_summary() -> str:
    """Return open repository counts, or a soft-failure note.

    Repository counts are helpful context for Telegram messages, but they are
    not important enough to fail the whole notification workflow when the
    GitHub API has a transient outage.
    """
    try:
        pull_requests, issues = open_repository_counts()
    except (RuntimeError, TimeoutError, urllib.error.URLError) as error:
        print(f"warning: unable to fetch repository counts: {error}")
        return "Open PRs: unavailable | Open issues: unavailable"

    return f"Open PRs: {pull_requests} | Open issues: {issues}"


def main() -> None:
    """Create a notification for CI, pull request, issue, or manual events."""
    payload = event_payload()
    event = os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch")
    repo_url = f"{server_url()}/{repository()}"

    if event == "workflow_run":
        run = payload["workflow_run"]
        conclusion = run.get("conclusion", "unknown").upper()
        branch = run.get("head_branch", "unknown")
        message = (
            f"MerkleForge CI {conclusion}\n\n"
            f"Branch: {branch}\n"
            f"Event: {run.get('event', 'unknown')}\n"
            f"Commit: {run.get('head_sha', '')[:8]}\n"
            f"Run: {run.get('html_url', repo_url)}"
        )
    elif event == "pull_request":
        pull = payload["pull_request"]
        message = (
            f"MerkleForge PR {payload.get('action', 'updated')}\n\n"
            f"#{pull['number']} {pull['title']}\n"
            f"Author: {pull['user']['login']}\n"
            f"Target: {pull['base']['ref']} <- {pull['head']['ref']}\n"
            f"{pull['html_url']}"
        )
    elif event == "issues":
        issue = payload["issue"]
        message = (
            f"MerkleForge issue {payload.get('action', 'updated')}\n\n"
            f"#{issue['number']} {issue['title']}\n"
            f"Author: {issue['user']['login']}\n"
            f"{issue['html_url']}"
        )
    else:
        message = (
            "MerkleForge notification test\n\n"
            f"Triggered by: {actor_name(payload)}\n"
            f"{repo_url}"
        )

    message += f"\n\n{repository_count_summary()}\n{repo_url}"
    Path("telegram_notification.txt").write_text(message + "\n")


if __name__ == "__main__":
    main()
