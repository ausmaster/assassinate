#!/bin/bash
# Local Docker test runner for all supported distros
# Usage: ./scripts/test-local.sh [distro]
# Example: ./scripts/test-local.sh kali
# Without arguments, tests all distros

set -e

DISTRO=${1:-all}

run_test() {
    local distro=$1
    local image=$2
    local script=$3

    echo "========================================="
    echo "Testing $distro"
    echo "========================================="

    docker run --rm \
        -v $(pwd):/workspace \
        -w /workspace \
        "$image" \
        bash /workspace/scripts/ci/"$script"

    echo "✓ $distro passed!"
    echo ""
}

if [ "$DISTRO" = "all" ] || [ "$DISTRO" = "kali" ]; then
    run_test "Kali Linux" "kalilinux/kali-rolling:latest" "test-kali.sh"
fi

if [ "$DISTRO" = "all" ] || [ "$DISTRO" = "parrot" ]; then
    run_test "Parrot Security" "parrotsec/security:latest" "test-parrot.sh"
fi

if [ "$DISTRO" = "all" ] || [ "$DISTRO" = "ubuntu" ]; then
    run_test "Ubuntu 24.04" "ubuntu:24.04" "test-debian-ubuntu.sh"
fi

if [ "$DISTRO" = "all" ] || [ "$DISTRO" = "debian" ]; then
    run_test "Debian" "debian:bookworm" "test-debian-ubuntu.sh"
fi

if [ "$DISTRO" = "all" ] || [ "$DISTRO" = "fedora" ]; then
    run_test "Fedora" "fedora:latest" "test-fedora.sh"
fi

if [ "$DISTRO" = "all" ] || [ "$DISTRO" = "arch" ]; then
    run_test "Arch Linux" "archlinux:latest" "test-arch.sh"
fi

if [ "$DISTRO" = "ubuntu-full" ]; then
    run_test "Ubuntu 24.04 Full" "ubuntu:24.04" "test-ubuntu-full.sh"
fi

echo "========================================="
echo "All tests passed!"
echo "========================================="
