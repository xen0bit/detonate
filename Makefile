# Detonate Makefile
# Common workflows for development, testing, and deployment

.PHONY: help install dev clean test test-cov lint typecheck build docker-build docker-run analyze samples samples-clean docker-test

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
install:
	uv sync

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

# Build test samples from source
samples:
	cd examples/samples && ./build_all.sh

# Remove compiled sample binaries
samples-clean:
	cd examples/samples && rm -f minimal_x86 minimal_x86_64 trigger_x8664 trigger_x86_64 fake_pe_x86.exe
	rm -rf examples/samples/data/*.json examples/samples/data/*.md
	@echo "Sample binaries cleaned"

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
