# Kube Workspaces workspace-agent — developer and packaging targets.
#
# Everything here is plain `cargo`; there is no code generation step and no
# container image (this repo ships guest-agent binaries, not a service).

BINARY   ?= kw-agent
CRATE    ?= kw-agent
BIN_DIR  ?= bin
DIST_DIR ?= dist

# VERSION is stamped into the binary at compile time (KW_AGENT_VERSION, read
# by kw_protocol::AGENT_VERSION). A tagged build gets the tag; anything else
# gets `<last-tag>-<n>-g<sha>[-dirty]`, or the bare sha in a shallow checkout
# with no tags. Local `cargo build` without the variable reports the crate
# version instead.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Release targets, one archive each. Built natively per target in CI (see
# .github/workflows/build.yml); `make package` consumes the downloaded
# binaries from $(BIN_DIR)/<target>/.
TARGETS := windows-amd64 linux-amd64 linux-arm64

.PHONY: help build release test clippy fmt lint package clean

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the debug workspace
	KW_AGENT_VERSION=$(VERSION) cargo build --workspace

release: ## Build the release kw-agent binary
	KW_AGENT_VERSION=$(VERSION) cargo build --release --locked -p $(CRATE)

test: ## Run the workspace test suite
	cargo test --workspace --locked

clippy: ## Run clippy with warnings denied
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## Format the workspace in place
	cargo fmt --all

lint: ## What CI runs: fmt check + clippy
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

# Stage and archive every release target from $(BIN_DIR)/<target>/ (CI
# downloads the per-target binaries there; locally you can place your own).
# Archive/stage names use the repository name (workspace-agent-<ver>-<os>-<arch>,
# root dir workspace-agent-<os>-<arch>) while the binary stays kw-agent — the
# contract scripts/verify-release-archives.py enforces. Windows archives carry
# the PowerShell enrollment scripts next to the exe, because the guest image
# recipe installs from the archive contents.
PACKAGE_NAME ?= workspace-agent
package: ## Stage and archive release targets from bin/<target>/
	@set -e; \
	for target in $(TARGETS); do \
		os=$${target%-*}; arch=$${target#*-}; \
		src="$(BIN_DIR)/$$target/$(BINARY)"; \
		if [ -f "$$src.exe" ]; then src="$$src.exe"; fi; \
		if [ ! -f "$$src" ]; then echo "error: missing $$src" >&2; exit 1; fi; \
		stage="$(DIST_DIR)/$(PACKAGE_NAME)-$$os-$$arch"; \
		rm -rf "$$stage"; mkdir -p "$$stage"; \
		cp "$$src" "$$stage/"; \
		chmod +x "$$stage/$$(basename "$$src")"; \
		cp README.md LICENSE "$$stage/"; \
		if [ "$$os" = windows ]; then \
			cp packaging/windows/install.ps1 packaging/windows/uninstall.ps1 "$$stage/"; \
		fi; \
		if [ "$$os" = windows ]; then \
			(cd $(DIST_DIR) && zip -qr "$(PACKAGE_NAME)-$(VERSION)-$$os-$$arch.zip" "$(PACKAGE_NAME)-$$os-$$arch"); \
		else \
			(cd $(DIST_DIR) && tar -czf "$(PACKAGE_NAME)-$(VERSION)-$$os-$$arch.tar.gz" "$(PACKAGE_NAME)-$$os-$$arch"); \
		fi; \
		echo "staged $$stage"; \
	done
	@cd $(DIST_DIR) && sha256sum *.tar.gz *.zip > SHA256SUMS
	@echo "packaged $(VERSION):"
	@ls -l $(DIST_DIR)/*.tar.gz $(DIST_DIR)/*.zip

clean: ## Remove build and packaging output
	cargo clean
	rm -rf $(DIST_DIR)
