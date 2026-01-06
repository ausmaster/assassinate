#!/bin/bash
# install_hooks.sh - Install git hooks for documentation verification
#
# Usage: ./scripts/install_hooks.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HOOKS_DIR="$PROJECT_ROOT/.git/hooks"

echo "Installing git hooks..."

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook: Verify documentation accuracy before allowing commits
#
# This hook runs verify_docs.sh to ensure CLAUDE.local.md counts match
# the actual codebase. If drift is detected, the commit is blocked.

SCRIPT_DIR="$(git rev-parse --show-toplevel)/scripts"

# Only run if we're modifying relevant files
RELEVANT_FILES=$(git diff --cached --name-only | grep -E '\.(rs|py|md)$' || true)

if [[ -n "$RELEVANT_FILES" ]]; then
    echo "Checking documentation accuracy..."

    if ! "$SCRIPT_DIR/verify_docs.sh"; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMMIT BLOCKED: Documentation is out of sync with code"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "Options:"
        echo "  1. Run: ./scripts/verify_docs.sh --fix"
        echo "  2. Then: git add CLAUDE.local.md"
        echo "  3. Then: git commit again"
        echo ""
        echo "Or bypass with: git commit --no-verify"
        echo ""
        exit 1
    fi
fi

exit 0
EOF

chmod +x "$HOOKS_DIR/pre-commit"

echo "✓ Pre-commit hook installed at .git/hooks/pre-commit"
echo ""
echo "The hook will verify documentation on each commit."
echo "To bypass: git commit --no-verify"
