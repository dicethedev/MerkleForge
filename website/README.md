# MerkleForge Website

This directory contains the source for the official MerkleForge GitHub Pages
site.

## Structure

```text
website/
├── build.py                  # static-site build and Criterion data injection
└── src/
    ├── assets/
    │   ├── app.js            # navigation and benchmark rendering
    │   └── styles.css        # shared visual system
    ├── index.html            # project landing page
    ├── benchmarks/index.html # interactive benchmark dashboard
    ├── docs/index.html       # architecture and API guide
    └── examples/index.html   # copy-pasteable Rust examples
```

Criterion's generated reports are not stored here. The Pages workflow runs
the benchmarks, copies the reports into `_site/reports/criterion/`, and then
calls `build.py` to generate the official site.

## Local Preview

Run the binary-tree benchmark first when `target/criterion` is missing or
outdated:

```bash
cargo bench --bench binary_tree
```

Build and serve the site:

```bash
rm -rf /tmp/merkleforge-site
mkdir -p /tmp/merkleforge-site/reports/criterion
cp -R target/criterion/. /tmp/merkleforge-site/reports/criterion/

python3 website/build.py \
  --output /tmp/merkleforge-site \
  --criterion-dir target/criterion

python3 -m http.server 8765 \
  --bind 127.0.0.1 \
  --directory /tmp/merkleforge-site
```

Open <http://127.0.0.1:8765/>.

## Editing

- Edit page content under `website/src/`.
- Keep common presentation rules in `website/src/assets/styles.css`.
- Keep shared interactions and benchmark rendering in
  `website/src/assets/app.js`.
- Do not edit generated `_site` output.
