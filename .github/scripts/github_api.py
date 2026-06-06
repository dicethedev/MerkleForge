"""Small GitHub API helpers used by repository automation."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any


def repository() -> str:
    """Return the current owner/repository identifier."""
    value = os.environ.get("GH_REPOSITORY") or os.environ.get("GITHUB_REPOSITORY")
    if not value:
        raise RuntimeError("GH_REPOSITORY or GITHUB_REPOSITORY is required")
    return value


def server_url() -> str:
    """Return the GitHub server URL."""
    return os.environ.get("GH_SERVER_URL", "https://github.com").rstrip("/")


def api_get(path: str, query: dict[str, str] | None = None) -> Any:
    """Fetch and decode a GitHub REST API response."""
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    url = f"{api_url}/{path.lstrip('/')}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "MerkleForge-Actions",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def open_repository_counts() -> tuple[int, int]:
    """Return counts of open pull requests and non-PR issues."""
    items = api_get(
        f"repos/{repository()}/issues",
        {"state": "open", "per_page": "100"},
    )
    pull_requests = sum("pull_request" in item for item in items)
    issues = len(items) - pull_requests
    return pull_requests, issues
