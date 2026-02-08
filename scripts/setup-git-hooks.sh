#!/bin/bash
# Setup git hooks for Tsun development
# Run this after cloning the repository

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "🔧 Setting up git hooks for Tsun..."

# Install pre-push hook
echo "  → Installing pre-push hook..."
cat > "$HOOKS_DIR/pre-push" << 'EOF'
#!/bin/bash
# Pre-push hook for Tsun
# Ensures code quality before pushing to remote

set -e

echo "🔍 Running pre-push checks..."

# 1. Check formatting
echo "  → Checking code formatting..."
if ! cargo fmt --check --quiet; then
    echo "❌ Code is not formatted properly"
    echo "   Run: cargo fmt"
    exit 1
fi
echo "  ✓ Formatting OK"

# 2. Run clippy with strict warnings
echo "  → Running clippy checks..."
if ! cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep -q "Finished"; then
    echo "❌ Clippy found issues"
    echo "   Run: cargo clippy --all-targets --all-features -- -D warnings"
    exit 1
fi
echo "  ✓ Clippy OK"

# 3. Run tests
echo "  → Running tests..."
if ! cargo test --lib --quiet; then
    echo "❌ Tests failed"
    echo "   Run: cargo test --lib"
    exit 1
fi
echo "  ✓ Tests OK"

echo "✅ All pre-push checks passed!"
exit 0
EOF

chmod +x "$HOOKS_DIR/pre-push"
echo "  ✓ Pre-push hook installed"

echo ""
echo "✅ Git hooks successfully installed!"
echo ""
echo "The pre-push hook will automatically run before each push to ensure:"
echo "  - Code is properly formatted (cargo fmt)"
echo "  - No clippy warnings (cargo clippy)"
echo "  - All tests pass (cargo test)"
echo ""
echo "You can run checks manually:"
echo "  cargo fmt"
echo "  cargo clippy --all-targets --all-features -- -D warnings"
echo "  cargo test --lib"
