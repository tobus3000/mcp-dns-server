#!/bin/bash
# Code quality checks with ruff

# Check for linting issues
echo "Running ruff linter..."
ruff check src/ tests/

# Check formatting (dry-run)
echo "Checking code format..."
ruff format src/ tests/ --check

# Format code
echo "Auto-formatting code..."
ruff format src/ tests/
