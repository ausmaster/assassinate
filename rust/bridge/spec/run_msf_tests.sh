#!/bin/bash
#
# Run Metasploit RSpec tests through our Rust FFI Bridge
#
# Usage:
#   ./spec/run_msf_tests.sh                           # Run all MSF tests
#   ./spec/run_msf_tests.sh framework                 # Run framework tests
#   ./spec/run_msf_tests.sh path/to/specific_spec.rb  # Run specific test file
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BRIDGE_ROOT="$(dirname "$SCRIPT_DIR")"
MSF_ROOT="${MSF_ROOT:-$(dirname "$BRIDGE_ROOT")/metasploit-framework}"

echo -e "${YELLOW}=== Assassinate Bridge Test Runner ===${NC}"
echo "Bridge root: $BRIDGE_ROOT"
echo "MSF root: $MSF_ROOT"
echo ""

# Check if MSF exists
if [ ! -d "$MSF_ROOT" ]; then
    echo -e "${RED}ERROR: Metasploit Framework not found at $MSF_ROOT${NC}"
    echo "Set MSF_ROOT environment variable to point to your MSF installation"
    exit 1
fi

# Check if bridge is built
if [ ! -f "$BRIDGE_ROOT/target/debug/libassassinate_bridge.so" ] && \
   [ ! -f "$BRIDGE_ROOT/target/debug/libassassinate_bridge.dylib" ]; then
    echo -e "${YELLOW}Bridge library not found. Building...${NC}"
    cd "$BRIDGE_ROOT"
    cargo build
    echo -e "${GREEN}Build complete${NC}\n"
fi

# Export environment variables
export MSF_ROOT="$MSF_ROOT"
export RAILS_ENV=test

# Determine what to test
if [ -z "$1" ]; then
    # Run all framework core tests
    TEST_PATH="$MSF_ROOT/spec/lib/msf/core/framework_spec.rb"
    echo -e "${GREEN}Running framework core tests...${NC}\n"
elif [ -f "$1" ]; then
    # Absolute path provided
    TEST_PATH="$1"
    echo -e "${GREEN}Running test: $(basename $TEST_PATH)${NC}\n"
elif [ -f "$MSF_ROOT/$1" ]; then
    # Relative path from MSF root
    TEST_PATH="$MSF_ROOT/$1"
    echo -e "${GREEN}Running test: $1${NC}\n"
else
    # Try to find test by pattern
    TEST_PATH="$MSF_ROOT/spec/lib/msf/core/${1}_spec.rb"
    if [ ! -f "$TEST_PATH" ]; then
        echo -e "${RED}ERROR: Test not found: $1${NC}"
        echo "Try one of:"
        echo "  - framework"
        echo "  - module_manager"
        echo "  - data_store"
        echo "  - Or provide full path to spec file"
        exit 1
    fi
    echo -e "${GREEN}Running ${1} tests...${NC}\n"
fi

# Run the tests
cd "$MSF_ROOT"
bundle exec rspec \
    --require "$BRIDGE_ROOT/spec/bridge_spec_helper.rb" \
    --format documentation \
    --color \
    "$TEST_PATH"

echo ""
echo -e "${GREEN}=== Test run complete ===${NC}"
