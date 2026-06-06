.PHONY: fmt lint test

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
