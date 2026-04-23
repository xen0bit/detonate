# Detonate Makefile
# Common workflows for development, testing, and deployment

.PHONY: help install dev clean test test-cov lint typecheck build docker-build docker-run analyze samples samples-clean samples-go samples-go-cross samples-cross docker-test web-dev web-download-deps web-lint web-build test-web rootfs-init rootfs-update rootfs-list rootfs-clean

# Default target
help:
	@echo "Detonate - Malware Analysis Platform"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  install       Install dependencies with uv"
	@echo "  dev           Install dev dependencies"
	@echo "  clean         Remove build artifacts and caches"
	@echo ""
	@echo "Testing:"
	@echo "  test          Run all tests"
	@echo "  test-cov      Run tests with coverage"
	@echo "  test-e2e      Run end-to-end tests with samples"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint          Run ruff linter"
	@echo "  lint-fix      Auto-fix linting issues"
	@echo "  typecheck     Run mypy type checker"
	@echo "  format        Format code with black"
	@echo "  check         Run all checks (lint, typecheck, test)"
	@echo ""
	@echo "Samples:"
	@echo "  samples       Build test samples from source"
	@echo "  samples-clean Remove compiled sample binaries"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build  Build Docker image"
	@echo "  docker-run    Run Docker container"
	@echo "  docker-test   Test Docker image with samples"
	@echo ""
	@echo "Analysis:"
	@echo "  analyze       Analyze a sample (requires SAMPLE_PATH)"

# Python interpreter from uv
PYTHON := uv run python
DETONATE := uv run detonate

# Install dependencies
install: rootfs-init
	@echo ""
	@echo "Installing Python dependencies with uv..."
	uv sync
	@echo ""
	@echo "========================================"
	@echo "Installation complete!"
	@echo "========================================"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Build test samples: make samples"
	@echo "  2. Run end-to-end tests: make test-e2e"
	@echo "  3. Analyze a sample: detonate analyze <binary>"
	@echo ""
	@echo "For Windows binary analysis:"
	@echo "  - See WINDOWS_DLL_SETUP.md for DLL setup"
	@echo ""

# =============================================================================
# Rootfs Management
# =============================================================================

# Initialize Qiling rootfs submodule (first-time setup)
# Uses shallow clone (--depth 1) for fast initialization
rootfs-init:
	@echo "========================================"
	@echo "Initializing Qiling rootfs submodule..."
	@echo "========================================"
	@if git submodule status data/qiling_rootfs 2>/dev/null | grep -q "^-"; then \
		echo "✓ Rootfs submodule registered but not initialized"; \
		echo "Initializing submodule..."; \
		git submodule update --init data/qiling_rootfs; \
	elif [ -d "data/qiling_rootfs" ] && [ -f "data/qiling_rootfs/.git" ]; then \
		echo "✓ Rootfs submodule already exists"; \
		echo "Updating to latest version..."; \
		git submodule update --remote data/qiling_rootfs; \
	else \
		echo "Cloning Qiling rootfs repository (shallow clone)..."; \
		git submodule add --depth 1 https://github.com/qilingframework/rootfs.git data/qiling_rootfs; \
	fi
	@echo ""
	@echo "Available rootfs architectures:"
	@ls -1 data/qiling_rootfs/ | grep -E "_(linux|windows)$$" | while read dir; do \
		echo "  - $$dir"; \
	done
	@echo ""
	@echo "Priority architectures (tested):"
	@echo "  ✓ x86_64 (x8664_linux)"
	@echo "  ✓ x86 (x86_linux)"
	@echo "  ✓ arm64 (arm64_linux)"
	@echo ""
	@echo "Extended architectures (community support):"
	@echo "  - arm (arm_linux)"
	@echo "  - mips (mips32_linux)"
	@echo "  - mipsel (mips32el_linux)"
	@echo "  - riscv64 (riscv64_linux)"
	@echo ""
	@echo "========================================"
	@echo "Rootfs initialization complete!"
	@echo "========================================"

# Update rootfs submodule to latest version
rootfs-update:
	@echo "Updating Qiling rootfs submodule to latest version..."
	git submodule update --remote data/qiling_rootfs
	@echo "✓ Rootfs updated successfully"
	@echo ""
	@echo "Run 'make rootfs-list' to see available architectures"

# List available rootfs architectures
rootfs-list:
	@echo "Available Qiling rootfs architectures:"
	@echo ""
	@echo "Linux:"
	@ls -1 data/qiling_rootfs/ | grep "_linux$$" | while read dir; do \
		echo "  - $$dir"; \
	done
	@echo ""
	@echo "Windows (user-provided DLLs required):"
	@echo "  - x86_windows (data/rootfs/x86_windows/dlls/)"
	@echo "  - x8664_windows (data/rootfs/x8664_windows/dlls/)"
	@echo ""
	@echo "See WINDOWS_DLL_SETUP.md for Windows DLL setup instructions"

# Clean rootfs (use with caution - removes submodule)
rootfs-clean:
	@echo "WARNING: This will remove the Qiling rootfs submodule!"
	@echo "You will need to run 'make rootfs-init' to re-download."
	@echo ""
	@if [ "$(FORCE)" = "1" ] || [ -t 0 ]; then \
		if [ "$(FORCE)" = "1" ]; then \
			echo "FORCE=1 set - skipping confirmation"; \
		else \
			read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 0; \
		fi; \
		echo "Removing rootfs submodule..."; \
		git submodule deinit --force data/qiling_rootfs 2>/dev/null || true; \
		rm -rf data/qiling_rootfs; \
		git config --remove-section submodule.data/qiling_rootfs 2>/dev/null || true; \
		echo "✓ Rootfs submodule removed"; \
		echo ""; \
		echo "To re-initialize: make rootfs-init"; \
	else \
		echo "Not running in interactive mode."; \
		echo "Use 'make rootfs-clean FORCE=1' to force removal in CI/automation."; \
		exit 1; \
	fi

# Install with dev dependencies
dev:
	uv sync --all-extras

# Clean build artifacts
clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache
	rm -rf .venv uv.lock
	rm -rf build dist *.egg-info
	rm -rf htmlcov .coverage coverage.xml
	rm -rf output/*.json output/*.md output/*.txt
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "Clean complete"

# Run tests
test:
	uv run pytest

# Run tests with coverage
test-cov:
	uv run pytest --cov=src/detonate --cov-report=html --cov-report=term-missing

# Run end-to-end tests
test-e2e:
	cd examples/samples && ./test_e2e.sh

# Run linter
lint:
	uv run ruff check src tests

# Auto-fix linting issues
lint-fix:
	uv run ruff check --fix src tests

# Run type checker
typecheck:
	uv run mypy src

# Format code
format:
	uv run black src tests

# Run all checks
check: lint typecheck test

# Build test samples from source (C + Go)
samples:
	cd examples/samples && ./build_all.sh
	@echo ""
	@echo "All samples built (C + Go)"
	@echo ""
	@echo "C samples:"
	@echo "  - trigger_syscalls_c (x86_64, comprehensive syscall coverage)"
	@echo "  - trigger_syscalls_c_arm64 (ARM64 cross-compile)"
	@echo "  - trigger_x86_64 (x86_64, basic syscall coverage)"
	@echo ""
	@echo "Go samples:"
	@echo "  - trigger_syscalls_go (x86_64, may not fully emulate in Qiling)"
	@echo "  - trigger_syscalls_go_arm64 (ARM64 cross-compile)"

# Remove compiled sample binaries
samples-clean:
	cd examples/samples && rm -f minimal_x86 minimal_x86_64 trigger_x8664 trigger_x86_64 fake_pe_x86.exe trigger_syscalls trigger_syscalls_arm64
	rm -rf examples/samples/data/*.json examples/samples/data/*.md
	@echo "Sample binaries cleaned"

# Build Go samples (x86_64 native)
# Note: Go runtime initialization is complex and may not fully emulate in Qiling.
# For best results with detonate, use the C trigger_x86_64 sample.
samples-go:
	@echo "Building Go samples (x86_64)..."
	cd examples/samples && GO111MODULE=off CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls trigger_syscalls.go 2>&1 | grep -v "warning:" || true
	@echo "Go x86_64 sample built: examples/samples/trigger_syscalls"
	@echo ""
	@echo "Verifying static linking..."
	@if ldd examples/samples/trigger_syscalls 2>&1 | grep -q "not a dynamic executable"; then \
		echo "✓ trigger_syscalls is statically linked"; \
	else \
		echo "WARNING: trigger_syscalls may have dynamic dependencies"; \
	fi

# Build Go samples with cross-compilation (x86_64 + ARM64)
samples-go-cross: samples-go
	@echo ""
	@echo "Building Go samples (ARM64 cross-compile)..."
	cd examples/samples && GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls_arm64 trigger_syscalls.go 2>&1 | grep -v "warning:" || true
	@echo "Go ARM64 sample built: examples/samples/trigger_syscalls_arm64"
	@echo ""
	@echo "Verifying static linking..."
	@if ldd examples/samples/trigger_syscalls_arm64 2>&1 | grep -q "not a dynamic executable"; then \
		echo "✓ trigger_syscalls_arm64 is statically linked"; \
	else \
		echo "WARNING: trigger_syscalls_arm64 may have dynamic dependencies"; \
	fi

# Cross-compile all samples
samples-cross: samples-go-cross
	@echo ""
	@echo "Cross-compilation complete"
	@echo "Architectures: x86_64, arm64"

# Build Docker image
docker-build:
	docker build -t detonate:latest .

# Run Docker container (interactive)
docker-run:
	docker run --rm -it \
		-v $(pwd)/samples:/samples:ro \
		-v $(pwd)/output:/output \
		detonate:latest bash

# Test Docker image with samples
docker-test: docker-build
	docker run --rm \
		-v $(pwd)/examples/samples:/samples:ro \
		-v $(pwd)/output:/output \
		detonate:latest analyze /samples/trigger_x86_64 --platform linux --arch x86_64 --output /output

# Analyze a sample (set SAMPLE_PATH, e.g., make analyze SAMPLE_PATH=/path/to/sample)
analyze:
ifndef SAMPLE_PATH
	$(error SAMPLE_PATH is not set. Usage: make analyze SAMPLE_PATH=/path/to/sample)
endif
	$(DETONATE) analyze $(SAMPLE_PATH) --format all --output ./output

# Database commands
db-init:
	$(DETONATE) db init

db-migrate:
	$(DETONATE) db migrate

# Start API server
serve:
	$(DETONATE) serve --host 0.0.0.0 --port 8000

# Lock dependencies
lock:
	uv lock

# Update dependencies
update:
	uv lock --upgrade

# Web UI development
web-dev:
	@echo "Starting web development..."
	@echo "Open http://localhost:8000/web/ in your browser"

web-download-deps:
	@echo "Downloading web dependencies..."
	@mkdir -p web/js web/css
	@curl -L https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css -o web/css/pico.min.css
	@curl -L https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js -o web/js/chart.min.js
	@curl -L https://cdn.jsdelivr.net/npm/marked@12.0.0/marked.min.js -o web/js/marked.min.js
	@echo "Dependencies downloaded to web/js/ and web/css/"

web-lint:
	@echo "Web UI linting not configured (vanilla JS)"

web-build:
	@echo "Web UI build not required (static HTML)"

test-web:
	@echo "Web UI tests not configured"
