# MerkleForge Website

This directory contains the React + TypeScript source for the official
MerkleForge GitHub Pages site. The app is built with Vite and deployed as
static files.

## Structure

```text
website/
├── build.py                  # Criterion data generation + Vite build wrapper
├── index.html                # Vite HTML entrypoint
├── package.json              # React/Vite toolchain
├── vite.config.ts            # Pages base-path configuration
└── src/
    ├── assets/
    │   └── styles.css        # shared visual system
    ├── components/           # reusable UI blocks
    ├── data/                 # static snippets and default runtime data
    ├── hooks/                # reusable React hooks
    ├── layout/               # shared app shell and navigation
    ├── pages/                # route-level page views
    ├── types/                # shared TypeScript types
    ├── utils/                # formatting and path helpers
    ├── main.tsx              # React entrypoint and page selection
    └── vite-env.d.ts         # Vite TypeScript types
```

Criterion's generated reports are not stored here. The Pages workflow runs
the benchmarks, copies the reports into `_site/reports/criterion/`, and then
calls `build.py` to generate the official site.

## Local Preview

Run the benchmarks first when `target/criterion` is missing or outdated:

```bash
cargo bench --bench hash_throughput
cargo bench --bench binary_tree
cargo bench --bench sparse_tree
cargo bench --bench patricia_trie
```

Build and serve the site:

```bash
npm --prefix website ci

rm -rf /tmp/merkleforge-site
mkdir -p /tmp/merkleforge-site/reports/criterion
cp -R target/criterion/. /tmp/merkleforge-site/reports/criterion/

python3 website/build.py \
  --output /tmp/merkleforge-site \
  --criterion-dir target/criterion \
  --base-path /

python3 -m http.server 8765 \
  --bind 127.0.0.1 \
  --directory /tmp/merkleforge-site
```

Open <http://127.0.0.1:8765/>.

For component development, use Vite directly:

```bash
npm --prefix website run dev
```

## Editing

- Edit page-level content in `website/src/pages/`.
- Edit reusable UI components in `website/src/components/`.
- Edit shared app chrome in `website/src/layout/`.
- Edit helper functions in `website/src/utils/` and shared types in
  `website/src/types/`.
- Keep common presentation rules in `website/src/assets/styles.css`.
- Keep benchmark data generation in `website/build.py`.
- Do not edit generated `_site` output.
