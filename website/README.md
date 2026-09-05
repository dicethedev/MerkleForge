# MerkleForge Website

> React + TypeScript documentation site for MerkleForge Framework.

The website is a static Vite app deployed to GitHub Pages. It contains the
landing page, docs, examples, live demo, benchmark summary, and links to raw
Criterion reports.

## Directory Layout

```text
website/
├── build.py                  # Builds the static site and prepares benchmark data
├── index.html                # Vite HTML entrypoint
├── package.json              # Node scripts and frontend dependencies
├── vite.config.ts            # GitHub Pages base-path configuration
└── src/
    ├── assets/               # Shared CSS and visual assets
    ├── components/           # Reusable UI components
    ├── data/                 # Static snippets and default data
    ├── hooks/                # React hooks
    ├── layout/               # App shell and navigation
    ├── pages/                # Route-level page views
    ├── types/                # Shared TypeScript types
    ├── utils/                # Formatters and path helpers
    └── main.tsx              # Route selection and React entrypoint
```

Do not edit generated `_site/` output. Update the source files in `website/src`
instead.

## Local Development

Install dependencies:

```bash
npm --prefix website ci
```

Start Vite:

```bash
npm --prefix website run dev
```

Build the frontend:

```bash
npm --prefix website run build
```

## Full Static Site Build

Run benchmark targets first when `target/criterion` is missing or stale:

```bash
cargo bench --bench hash_throughput
cargo bench --bench binary_tree
cargo bench --bench sparse_tree
cargo bench --bench patricia_trie
```

Build the deployable site:

```bash
python3 website/build.py \
  --output _site \
  --criterion-dir target/criterion \
  --base-path /MerkleForge/
```

Preview the generated static output:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory _site
```

Open <http://127.0.0.1:8765/>.

## Editing Guide

- Page copy lives in `website/src/pages/`.
- Shared cards, code blocks, buttons, and visual sections live in
  `website/src/components/`.
- Shared shell/navigation lives in `website/src/layout/`.
- Benchmark parsing and static data generation live in `website/build.py`.
- Styling lives in `website/src/assets/styles.css`.

Keep UI components reusable and keep route-level content inside `pages/`.

## Deployment

The GitHub Actions workflow at `.github/workflows/website.yml` builds the
website, prepares the Pages artifact, and deploys it to:

<https://dicethedev.github.io/MerkleForge/>
