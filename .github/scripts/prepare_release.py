#!/usr/bin/env python3
"""Prepare a MerkleForge workspace release.

This script updates the workspace version in ``Cargo.toml``, promotes the
``[Unreleased]`` changelog section to the requested version, and writes the
promoted changelog entry to a release body file for GitHub Releases.
"""

from __future__ import annotations

import argparse
import re
from datetime import date
from pathlib import Path


VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
WORKSPACE_VERSION_RE = re.compile(r'(?m)^version\s*=\s*"[^"]+"')
CHANGELOG_VERSION_RE = re.compile(r"(?m)^## \[(?:v)?(?P<version>\d+\.\d+\.\d+)\]")
UNRELEASED_LINK_RE = re.compile(
    r"(?m)^\[Unreleased\]: (?P<base>.+/compare)/v(?P<previous>[^.\s]+\.[^.\s]+\.[^.\s]+)\.\.\.HEAD$"
)
UNRELEASED_HEADING = "## [Unreleased]"
SECTION_BREAK = "\n---\n"
EMPTY_UNRELEASED = "No unreleased changes yet."


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version, for example 0.4.1")
    parser.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="release date in YYYY-MM-DD format; defaults to today",
    )
    parser.add_argument(
        "--release-body",
        default="release_body.md",
        help="file to write the promoted changelog section to",
    )
    return parser.parse_args()


def validate_version(version: str) -> None:
    """Reject versions that are not plain semantic versions."""
    if not VERSION_RE.fullmatch(version):
        raise SystemExit(f"invalid version '{version}'; expected X.Y.Z")


def update_workspace_version(path: Path, version: str) -> None:
    """Update the first workspace package version assignment."""
    text = path.read_text()
    updated, replacements = WORKSPACE_VERSION_RE.subn(f'version = "{version}"', text, count=1)
    if replacements != 1:
        raise SystemExit(f"could not find workspace version in {path}")
    path.write_text(updated)


def update_changelog(path: Path, version: str, release_date: str, body_path: Path) -> None:
    """Promote the Unreleased section and write the release body."""
    text = path.read_text()
    previous_match = CHANGELOG_VERSION_RE.search(text)
    previous_version = previous_match.group("version") if previous_match else None
    heading_index = text.find(UNRELEASED_HEADING)
    if heading_index == -1:
        raise SystemExit(f"{path} does not contain {UNRELEASED_HEADING}")

    body_start = heading_index + len(UNRELEASED_HEADING)
    next_break = text.find(SECTION_BREAK, body_start)
    if next_break == -1:
        raise SystemExit(f"could not find end of Unreleased section in {path}")

    unreleased_body = text[body_start:next_break].strip()
    if not unreleased_body:
        unreleased_body = EMPTY_UNRELEASED

    release_heading = f"## [v{version}] — {release_date}"
    release_entry = f"{release_heading}\n\n{unreleased_body}\n"
    new_unreleased = f"{UNRELEASED_HEADING}\n\n{EMPTY_UNRELEASED}\n"
    updated = text[:heading_index] + new_unreleased + SECTION_BREAK + release_entry + text[next_break:]
    updated = update_changelog_links(updated, version, previous_version)

    path.write_text(updated)
    body_path.write_text(f"{release_heading}\n\n{unreleased_body}\n")


def update_changelog_links(text: str, version: str, previous_version: str | None) -> str:
    """Refresh bottom-of-file changelog comparison links."""
    link_match = UNRELEASED_LINK_RE.search(text)
    if not link_match:
        return text

    base = link_match.group("base")
    previous = previous_version or link_match.group("previous")
    unreleased = f"[Unreleased]: {base}/v{version}...HEAD"
    release_link = f"[v{version}]: {base}/v{previous}...v{version}"

    updated = UNRELEASED_LINK_RE.sub(unreleased, text, count=1)
    if f"[v{version}]:" in updated:
        return updated

    return updated.replace(unreleased, f"{unreleased}\n{release_link}", 1)


def main() -> None:
    """Run release preparation."""
    args = parse_args()
    validate_version(args.version)
    update_workspace_version(Path("Cargo.toml"), args.version)
    update_changelog(Path("CHANGELOG.md"), args.version, args.date, Path(args.release_body))


if __name__ == "__main__":
    main()
