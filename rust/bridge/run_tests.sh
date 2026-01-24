#!/bin/bash
# Test runner for Magnus-based Rust project with RVM Ruby
#
# This script properly configures the environment to run cargo test
# with an RVM-installed Ruby that has Metasploit Framework gems.
#
# Usage:
#   ./run_tests.sh                           # Run all tests
#   ./run_tests.sh --test test_framework_init  # Run specific test
#   ./run_tests.sh -- --nocapture            # Pass args to test binary

set -e

# Configuration
RVM_RUBY_VERSION="3.3.8"
MSF_ROOT="${MSF_ROOT:-$HOME/Projects/metasploit-framework}"

echo "========================================="
echo "Magnus/RVM Test Runner"
echo "========================================="
echo ""

# Load RVM and switch to Ruby 3.3.8
if [ ! -f "$HOME/.rvm/scripts/rvm" ]; then
    echo "ERROR: RVM not found at ~/.rvm/scripts/rvm"
    echo "Please install RVM and Ruby $RVM_RUBY_VERSION first"
    exit 1
fi

source "$HOME/.rvm/scripts/rvm"
rvm use "$RVM_RUBY_VERSION" || {
    echo "ERROR: Ruby $RVM_RUBY_VERSION not found"
    echo "Install with: rvm install $RVM_RUBY_VERSION"
    exit 1
}

# Export required environment variables
export RUBY=$(rvm which ruby)
export GEM_HOME="$HOME/.rvm/gems/ruby-$RVM_RUBY_VERSION"
export GEM_PATH="$HOME/.rvm/gems/ruby-$RVM_RUBY_VERSION:$HOME/.rvm/gems/ruby-$RVM_RUBY_VERSION@global"
export MSF_ROOT
export BUNDLE_GEMFILE="$MSF_ROOT/Gemfile"
export BUNDLE_WITHOUT="development test"

# Required for rb-sys bindgen with RVM Ruby
export BINDGEN_EXTRA_CLANG_ARGS="-std=gnu11 -include stdbool.h"

# Required for test binary to find libruby.so at runtime
export LD_LIBRARY_PATH=$(ruby -rrbconfig -e 'puts RbConfig::CONFIG["libdir"]')

# Print configuration
echo "Ruby: $RUBY"
echo "Ruby Version: $(ruby --version)"
echo "GEM_HOME: $GEM_HOME"
echo "MSF_ROOT: $MSF_ROOT"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo ""

# Run tests
echo "Running cargo test..."
echo "========================================="
cargo test "$@"
