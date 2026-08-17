.PHONY: fmt lint test install-release-tools install-profiling-tools

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-features -- \
		-W clippy::pedantic \
		-W clippy::nursery \
		-A clippy::module_name_repetitions \
		-D warnings

test:
	cargo test --workspace --release

install-release-tools:
	cargo install cargo-release --locked

install-profiling-tools:
	cargo install flamegraph --locked
