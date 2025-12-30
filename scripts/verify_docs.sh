#!/bin/bash
# verify_docs.sh - Verify CLAUDE.local.md documentation accuracy
#
# This script checks that documented method counts match actual code.
# Run after adding features to catch documentation drift.
#
# Usage: ./scripts/verify_docs.sh [--fix]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLAUDE_MD="$PROJECT_ROOT/CLAUDE.local.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track if any discrepancies found
DISCREPANCIES=0

# ==============================================================================
# Counting Functions
# ==============================================================================

count_rust_bridge_methods() {
    # Count public functions in the framework module files
    # Excludes test files and helper functions (starting with _)
    local count=0
    for file in "$PROJECT_ROOT"/rust/bridge/src/framework/*.rs; do
        if [[ -f "$file" ]]; then
            # Count 'pub fn' declarations (public methods)
            local file_count=$(grep -c 'pub fn ' "$file" 2>/dev/null || echo 0)
            count=$((count + file_count))
        fi
    done
    echo "$count"
}

count_daemon_handlers() {
    # Count IPC message handler match arms in main.rs
    # Pattern: "method_name" => { ... }
    local daemon_file="$PROJECT_ROOT/rust/daemon/src/main.rs"
    if [[ -f "$daemon_file" ]]; then
        # Count quoted strings followed by => (handler match arms)
        grep -cE '"[a-z_]+" =>' "$daemon_file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

count_python_async_methods() {
    # Count async def declarations in the client
    local client_file="$PROJECT_ROOT/python/assassinate/ipc/client.py"
    if [[ -f "$client_file" ]]; then
        grep -c 'async def ' "$client_file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# ==============================================================================
# Documentation Parsing
# ==============================================================================

get_documented_count() {
    local pattern="$1"
    # Extract the number from lines like "- Rust Bridge: 151 methods"
    grep -oP "$pattern: \K[0-9]+" "$CLAUDE_MD" 2>/dev/null || echo "0"
}

# ==============================================================================
# Verification
# ==============================================================================

verify_count() {
    local name="$1"
    local documented="$2"
    local actual="$3"

    if [[ "$documented" -eq "$actual" ]]; then
        echo -e "${GREEN}✓${NC} $name: $actual (matches documentation)"
    else
        echo -e "${RED}✗${NC} $name: documented=$documented, actual=$actual (diff: $((actual - documented)))"
        DISCREPANCIES=1
    fi
}

# ==============================================================================
# Main
# ==============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Documentation Verification: CLAUDE.local.md"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Get actual counts
echo "Counting methods in source code..."
ACTUAL_RUST=$(count_rust_bridge_methods)
ACTUAL_DAEMON=$(count_daemon_handlers)
ACTUAL_PYTHON=$(count_python_async_methods)

echo ""

# Get documented counts
DOC_RUST=$(get_documented_count "Rust Bridge")
DOC_DAEMON=$(get_documented_count "Daemon Handlers")
DOC_PYTHON=$(get_documented_count "Python Client")

# Verify each
echo "Verification Results:"
echo "─────────────────────────────────────────────────────────────────────────"
verify_count "Rust Bridge methods" "$DOC_RUST" "$ACTUAL_RUST"
verify_count "Daemon Handlers" "$DOC_DAEMON" "$ACTUAL_DAEMON"
verify_count "Python Client methods" "$DOC_PYTHON" "$ACTUAL_PYTHON"
echo "─────────────────────────────────────────────────────────────────────────"
echo ""

# Summary
if [[ $DISCREPANCIES -eq 0 ]]; then
    echo -e "${GREEN}All documentation counts are accurate!${NC}"
    exit 0
else
    echo -e "${YELLOW}Documentation drift detected!${NC}"
    echo ""
    echo "To fix, update the 'Coverage Summary' section in CLAUDE.local.md:"
    echo ""
    echo "**Totals:**"
    echo "- Rust Bridge: $ACTUAL_RUST methods"
    echo "- Daemon Handlers: $ACTUAL_DAEMON handlers"
    echo "- Python Client: $ACTUAL_PYTHON async methods"
    echo ""

    # Auto-fix if requested
    if [[ "${1:-}" == "--fix" ]]; then
        echo "Applying fix..."

        # Use sed to update the counts in place
        sed -i "s/Rust Bridge: [0-9]* methods/Rust Bridge: $ACTUAL_RUST methods/" "$CLAUDE_MD"
        sed -i "s/Daemon Handlers: [0-9]* handlers/Daemon Handlers: $ACTUAL_DAEMON handlers/" "$CLAUDE_MD"
        sed -i "s/Python Client: [0-9]* async methods/Python Client: $ACTUAL_PYTHON async methods/" "$CLAUDE_MD"

        echo -e "${GREEN}Fixed! Documentation updated.${NC}"
        exit 0
    else
        echo "Run with --fix to automatically update documentation:"
        echo "  ./scripts/verify_docs.sh --fix"
        exit 1
    fi
fi
