#!/bin/bash
# Local CI validation script
# Runs the same checks that CI will run

set -e

echo "=========================================================================="
echo "Local CI Validation Script"
echo "=========================================================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILED=0

run_check() {
    local name="$1"
    local command="$2"

    echo -e "${YELLOW}▶ $name${NC}"
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ $name passed${NC}"
    else
        echo -e "${RED}✗ $name failed${NC}"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

# Rust Checks
echo "========== Rust Checks =========="
echo ""

run_check "Rust Format (IPC)" "cd rust/ipc && cargo fmt -- --check"
run_check "Rust Format (Bridge)" "cd rust/bridge && cargo fmt -- --check"
run_check "Rust Format (Daemon)" "cd rust/daemon && cargo fmt -- --check"

run_check "Clippy (IPC)" "cd rust/ipc && cargo clippy --all-targets -- -D warnings"
run_check "Clippy (Bridge)" "cd rust/bridge && cargo clippy --all-targets -- -D warnings"
run_check "Clippy (Daemon)" "cd rust/daemon && cargo clippy --all-targets -- -D warnings"

# Python Checks
echo "========== Python Checks =========="
echo ""

run_check "Python Format (Ruff)" "uv run ruff format --check ."
run_check "Python Lint (Ruff)" "uv run ruff check ."
run_check "Python Types (MyPy)" "uv run mypy assassinate || true"  # Non-blocking

# Build Checks
echo "========== Build Checks =========="
echo ""

run_check "Build IPC" "cd rust/ipc && cargo build --release"
run_check "Build Bridge" "cd rust/bridge && cargo build --release"
run_check "Build Daemon" "cd rust/daemon && cargo build --release"

# Test Suite
echo "========== Test Suite =========="
echo ""

echo -e "${YELLOW}▶ Running Python Integration Tests (118 tests)${NC}"
if ASSASSINATE_LOG_LEVEL=WARNING uv run pytest tests/ -v --tb=short --maxfail=5; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
    FAILED=$((FAILED + 1))
fi
echo ""

# Summary
echo "=========================================================================="
echo "Summary"
echo "=========================================================================="
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Ready for CI.${NC}"
    exit 0
else
    echo -e "${RED}✗ $FAILED check(s) failed. Please fix before pushing.${NC}"
    exit 1
fi
