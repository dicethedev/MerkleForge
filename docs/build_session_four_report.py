#!/usr/bin/env python3
"""Build the Session Four report source assets.

This script turns the Markdown report into a styled HTML source that
LibreOffice can export to DOCX/PDF. It also renders selected code excerpts as
PNG images so the report contains implementation evidence, not only UI shots.
"""

from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path

from markdown import markdown
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
ASSETS = DOCS / "assets" / "session-four"
MARKDOWN = DOCS / "session-four-implementation-and-testing.md"
HTML = DOCS / "session-four-implementation-and-testing.html"


CODE_SHOTS = [
    (
        "Cargo.toml",
        ROOT / "Cargo.toml",
        1,
        36,
        "code-workspace-manifest.png",
    ),
    (
        "merkle_tree.rs",
        ROOT / "merkle-core" / "src" / "traits" / "merkle_tree.rs",
        15,
        76,
        "code-merkle-tree-trait.png",
    ),
    (
        "sparse_properties.rs",
        ROOT / "merkle-variants" / "tests" / "sparse_properties.rs",
        58,
        111,
        "code-sparse-properties.png",
    ),
    (
        "ci.yml",
        ROOT / ".github" / "workflows" / "ci.yml",
        1,
        85,
        "code-ci-workflow.png",
    ),
]


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def render_code_shot(
    title: str,
    source: Path,
    start: int,
    end: int,
    output_name: str,
) -> None:
    lines = source.read_text().splitlines()
    selected = lines[start - 1 : end]
    numbered = [f"{line_no:>3}  {line}" for line_no, line in enumerate(selected, start)]

    font = load_font(22)
    title_font = load_font(24)
    line_height = 32
    padding_x = 34
    padding_y = 30
    title_gap = 48
    max_chars = max(len(line) for line in numbered)
    width = min(1800, max(980, padding_x * 2 + max_chars * 13))
    height = padding_y * 2 + title_gap + len(numbered) * line_height

    image = Image.new("RGB", (width, height), "#0b1017")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle(
        (8, 8, width - 8, height - 8),
        radius=26,
        fill="#101722",
        outline="#2e74b5",
        width=2,
    )
    draw.text((padding_x, padding_y), title, fill="#dbeafe", font=title_font)
    draw.line(
        (padding_x, padding_y + 34, width - padding_x, padding_y + 34),
        fill="#26364a",
        width=2,
    )

    y = padding_y + title_gap
    for line in numbered:
        if line.strip().startswith("//") or line.strip().startswith("#"):
            fill = "#8aa4bf"
        elif any(keyword in line for keyword in ("pub ", "fn ", "trait ", "impl ", "use ")):
            fill = "#b9f6ff"
        else:
            fill = "#e5edf7"
        draw.text((padding_x, y), line[:132], fill=fill, font=font)
        y += line_height

    image.save(ASSETS / output_name)


def insert_code_screenshots(markdown_text: str) -> str:
    insertion = """

### Codebase Screenshots

The following screenshots show selected parts of the implementation and CI
configuration used during system development.

![Figure 4.8: Workspace manifest and shared dependency versions](assets/session-four/code-workspace-manifest.png)

![Figure 4.9: Shared MerkleTree and ProofVerifier trait contract](assets/session-four/code-merkle-tree-trait.png)

![Figure 4.10: Sparse tree property-based tests](assets/session-four/code-sparse-properties.png)

![Figure 4.11: GitHub Actions CI workflow](assets/session-four/code-ci-workflow.png)

"""
    marker = "Recommended codebase screenshots to include in the final report:"
    return markdown_text.replace(marker, insertion + marker)


def html_source(markdown_text: str) -> str:
    body = markdown(
        markdown_text,
        extensions=["extra", "tables", "fenced_code", "sane_lists"],
        output_format="html5",
    )
    title = "Session Four: Implementation and Testing"
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    @page {{ size: Letter; margin: 1in; }}
    body {{
      font-family: Calibri, Arial, sans-serif;
      font-size: 11pt;
      line-height: 1.25;
      color: #1f2937;
    }}
    h1 {{
      color: #0b2545;
      font-size: 24pt;
      margin: 0 0 12pt;
      border-bottom: 2px solid #2e74b5;
      padding-bottom: 8pt;
    }}
    h2 {{
      color: #2e74b5;
      font-size: 16pt;
      margin: 18pt 0 8pt;
      break-after: avoid;
    }}
    h3 {{
      color: #1f4d78;
      font-size: 13pt;
      margin: 14pt 0 6pt;
      break-after: avoid;
    }}
    h4 {{
      color: #0b2545;
      font-size: 12pt;
      margin: 10pt 0 5pt;
      break-after: avoid;
    }}
    p {{
      margin: 0 0 7pt;
    }}
    ul, ol {{
      margin-top: 0;
      margin-bottom: 8pt;
    }}
    li {{
      margin-bottom: 3pt;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 8pt 0 14pt;
      font-size: 9.2pt;
      break-inside: auto;
    }}
    th {{
      background: #f2f4f7;
      color: #0b2545;
      font-weight: bold;
      border: 1px solid #c9d3df;
      padding: 6pt;
      text-align: left;
      vertical-align: middle;
    }}
    td {{
      border: 1px solid #d9e0e8;
      padding: 6pt;
      vertical-align: top;
    }}
    pre {{
      background: #0b1017;
      color: #e5edf7;
      border: 1px solid #2e74b5;
      padding: 10pt;
      font-family: Consolas, "Courier New", monospace;
      font-size: 8.5pt;
      white-space: pre-wrap;
      margin: 8pt 0 12pt;
    }}
    code {{
      font-family: Consolas, "Courier New", monospace;
      font-size: 9pt;
      color: #0b2545;
    }}
    pre code {{
      color: inherit;
      font-size: inherit;
    }}
    img {{
      display: block;
      max-width: 100%;
      height: auto;
      margin: 8pt auto 14pt;
      border: 1px solid #d9e0e8;
    }}
    blockquote {{
      border-left: 4px solid #2e74b5;
      margin: 8pt 0 12pt;
      padding: 6pt 10pt;
      background: #f4f6f9;
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    for shot in CODE_SHOTS:
        render_code_shot(*shot)

    markdown_text = MARKDOWN.read_text()
    markdown_text = insert_code_screenshots(markdown_text)
    HTML.write_text(html_source(markdown_text))


if __name__ == "__main__":
    main()
