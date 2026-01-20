# Ritma Makefile
# Build, test, and package Ritma

.PHONY: all build release test fmt clippy clean install deb

# Default target
all: build

# Development build
build:
	cargo build --workspace

# Release build
release:
	cargo build --release --workspace

# Run tests
test:
	cargo test --workspace

# Format code
fmt:
	cargo fmt --all

# Lint with clippy
clippy:
	cargo clippy --workspace --fix --allow-dirty --allow-staged

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/debian

# Install locally (requires root)
install: release
	sudo ./install.sh

# Build Debian package
deb: release
	@command -v cargo-deb >/dev/null 2>&1 || { \
		echo "Installing cargo-deb..."; \
		cargo install cargo-deb; \
	}
	cargo deb -p ritma_cli --no-build

# Build all binaries
binaries: release
	@echo "Built binaries:"
	@ls -la target/release/ritma
	@ls -la target/release/tracer_sidecar

# Run demo lab
demo:
	cd demo/lab && cargo build --release
	cd demo/lab && ./target/release/ritma-lab run \
		--scenario scenarios/baseline.yaml \
		--topology topologies/three-tier.yaml

# Generate documentation
docs:
	cargo doc --workspace --no-deps --open

# Check everything
check: fmt clippy test
	@echo "All checks passed!"

# Help
help:
	@echo "Ritma Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build    - Development build"
	@echo "  release  - Release build"
	@echo "  test     - Run tests"
	@echo "  fmt      - Format code"
	@echo "  clippy   - Lint with clippy"
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install locally (sudo)"
	@echo "  deb      - Build Debian package"
	@echo "  demo     - Run demo lab"
	@echo "  docs     - Generate documentation"
	@echo "  check    - Run all checks"
