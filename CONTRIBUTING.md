# Contributing to MerkleForge Framework

Thanks for helping improve MerkleForge Framework. Contributions are welcome
across correctness, documentation, benchmarks, examples, developer experience,
and performance analysis.

## Good First Contributions

- Improve README docs, Rustdoc, examples, or website explanations.
- Add benchmark reproduction notes for different hardware.
- Add test vectors for Binary, Sparse, or Patricia Merkle trees.
- Improve error messages or API examples.
- Investigate performance bottlenecks with Criterion, `perf`, or flamegraphs.

## Development Setup

```bash
git clone https://github.com/dicethedev/MerkleForge.git
cd MerkleForge
cargo test --workspace
```

For website work:

```bash
npm --prefix website ci
npm --prefix website run build
```

## Recommended Workflow

1. Open or comment on an issue for large API, storage, or cryptography changes.
2. Create a focused branch, for example `fix/docs-links` or
   `feat/sparse-proof-tests`.
3. Keep the pull request small enough to review comfortably.
4. Add or update tests for behavior changes.
5. Update docs when public APIs, examples, or benchmark behavior changes.

## Required Checks

Run these before opening a pull request:

```bash
make fmt
make lint
make test
```

For website changes, also run:

```bash
npm --prefix website run build
```

## Pull Request Guidelines

- Explain the problem, the change, and the verification performed.
- Link related issues.
- Keep generated `target/`, local benchmark noise, editor files, and temporary
  artifacts out of commits.
- Include benchmark numbers only when the environment and command are recorded.
- Avoid unrelated refactors in feature or bug-fix pull requests.

## Security

Please do not report vulnerabilities in public issues. Follow the responsible
disclosure process in [`.github/SECURITY.md`](.github/SECURITY.md).
