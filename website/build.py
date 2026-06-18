#!/usr/bin/env python3
"""Build the official MerkleForge static website."""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SOURCE_DIR = Path(__file__).parent / "src"
HTML_PAGES = (
    Path("index.html"),
    Path("docs/index.html"),
    Path("examples/index.html"),
    Path("benchmarks/index.html"),
)


def load_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from disk."""
    return json.loads(path.read_text())


def workspace_version(manifest_path: Path) -> str:
    """Read the shared package version from the workspace manifest."""
    manifest = tomllib.loads(manifest_path.read_text())
    return str(manifest["workspace"]["package"]["version"])


def parse_size(value: Any) -> float:
    """Return a sortable numeric benchmark input size."""
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return 0


def collect_benchmarks(criterion_dir: Path) -> list[dict[str, Any]]:
    """Collect completed Criterion estimates for the website dashboard."""
    benchmarks: list[dict[str, Any]] = []

    for benchmark_path in sorted(criterion_dir.glob("**/new/benchmark.json")):
        estimates_path = benchmark_path.with_name("estimates.json")
        if not estimates_path.exists():
            continue

        benchmark = load_json(benchmark_path)
        estimates = load_json(estimates_path)
        function_id = str(benchmark.get("function_id", "benchmark"))
        operation, separator, algorithm = function_id.partition("/")
        mean = estimates["mean"]
        confidence = mean["confidence_interval"]
        throughput = benchmark.get("throughput") or {}
        elements = throughput.get("Elements")
        mean_ns = float(mean["point_estimate"])

        benchmarks.append(
            {
                "id": str(benchmark["full_id"]),
                "operation": operation.replace("_", " ").title(),
                "operation_key": operation,
                "algorithm": algorithm if separator else "Default",
                "size": str(benchmark.get("value_str", "n/a")),
                "size_value": parse_size(benchmark.get("value_str")),
                "mean_ns": mean_ns,
                "lower_ns": float(confidence["lower_bound"]),
                "upper_ns": float(confidence["upper_bound"]),
                "elements_per_second": (
                    float(elements) * 1_000_000_000 / mean_ns
                    if (
                        operation == "construction"
                        and elements is not None
                        and mean_ns > 0
                    )
                    else None
                ),
                "report": (
                    "../reports/criterion/"
                    + str(benchmark["directory_name"])
                    + "/report/index.html"
                ),
            }
        )

    return benchmarks


def page_root(page: Path) -> str:
    """Return the relative path from a generated page to the site root."""
    return "" if page.parent == Path(".") else "../"


def render_page(
    page: Path,
    output_dir: Path,
    repository_url: str,
    crate_version: str,
    benchmark_payload: str,
) -> None:
    """Render one HTML template into the output directory."""
    root = page_root(page)
    source = (SOURCE_DIR / page).read_text()
    rendered = (
        source.replace("__ROOT__", root)
        .replace("__REPOSITORY_URL__", html.escape(repository_url, quote=True))
        .replace("__CRATE_VERSION__", html.escape(crate_version))
        .replace("__BENCHMARK_DATA__", benchmark_payload)
    )

    destination = output_dir / page
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered)


def build_site(
    output_dir: Path,
    criterion_dir: Path,
    repository_url: str,
    commit_sha: str,
    crate_version: str,
    minimum_samples: int,
) -> int:
    """Build all pages and return the number of benchmark samples."""
    benchmarks = collect_benchmarks(criterion_dir)
    if len(benchmarks) < minimum_samples:
        raise SystemExit(
            f"Expected at least {minimum_samples} completed benchmark samples, "
            f"found {len(benchmarks)}"
        )

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    payload = json.dumps(
        {
            "benchmarks": benchmarks,
            "generatedAt": generated_at,
            "commit": commit_sha[:7] if commit_sha else "local",
        },
        separators=(",", ":"),
    ).replace("</", "<\\/")

    assets_output = output_dir / "assets"
    if assets_output.exists():
        shutil.rmtree(assets_output)
    shutil.copytree(SOURCE_DIR / "assets", assets_output)

    for page in HTML_PAGES:
        render_page(
            page,
            output_dir,
            repository_url,
            crate_version,
            payload,
        )

    (output_dir / ".nojekyll").touch()
    return len(benchmarks)


def main() -> None:
    """Parse command-line arguments and build the website."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-dir", type=Path, default=Path("target/criterion"))
    parser.add_argument("--output", type=Path, default=Path("_site"))
    parser.add_argument("--minimum-samples", type=int, default=0)
    parser.add_argument(
        "--repository-url",
        default=(
            os.environ.get("GITHUB_SERVER_URL", "https://github.com")
            + "/"
            + os.environ.get("GITHUB_REPOSITORY", "dicethedev/MerkleForge")
        ),
    )
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument(
        "--crate-version",
        default=workspace_version(Path("Cargo.toml")),
    )
    args = parser.parse_args()

    sample_count = build_site(
        args.output,
        args.criterion_dir,
        args.repository_url,
        args.commit,
        args.crate_version,
        args.minimum_samples,
    )
    print(f"Generated {args.output} with {sample_count} benchmark samples")


if __name__ == "__main__":
    main()
