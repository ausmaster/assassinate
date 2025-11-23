#!/bin/bash
# Test Assassinate installation across multiple Linux distributions
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Available distros
DISTROS=("kali" "ubuntu" "debian" "arch" "fedora")

# Function to print colored output
print_status() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] ✓${NC} $1"
}

print_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠${NC} $1"
}

# Function to test a single distro
test_distro() {
    local distro=$1
    print_status "Testing $distro..."

    if docker compose build "$distro-test"; then
        print_success "$distro build completed successfully"
        return 0
    else
        print_error "$distro build failed"
        return 1
    fi
}

# Function to test all distros
test_all() {
    print_status "Testing all distributions..."
    local failed=()
    local succeeded=()

    for distro in "${DISTROS[@]}"; do
        echo ""
        echo "========================================"
        echo "Testing: $distro"
        echo "========================================"

        if test_distro "$distro"; then
            succeeded+=("$distro")
        else
            failed+=("$distro")
        fi
    done

    echo ""
    echo "========================================"
    echo "Test Results Summary"
    echo "========================================"
    echo -e "${GREEN}Succeeded (${#succeeded[@]}):${NC} ${succeeded[*]}"
    if [ ${#failed[@]} -gt 0 ]; then
        echo -e "${RED}Failed (${#failed[@]}):${NC} ${failed[*]}"
        return 1
    fi
    echo -e "${GREEN}All tests passed!${NC}"
    return 0
}

# Main script
if [ $# -eq 0 ]; then
    # No arguments - test all
    test_all
elif [ "$1" == "all" ]; then
    # Explicit all
    test_all
elif [ "$1" == "clean" ]; then
    # Clean up all test containers and images
    print_status "Cleaning up Docker test artifacts..."
    docker compose down --rmi all --volumes
    print_success "Cleanup complete"
else
    # Test specific distro
    distro=$1
    if [[ " ${DISTROS[@]} " =~ " ${distro} " ]]; then
        test_distro "$distro"
    else
        print_error "Unknown distro: $distro"
        echo "Available distros: ${DISTROS[*]}"
        exit 1
    fi
fi
