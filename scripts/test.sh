#!/usr/bin/env bash
# =============================================================================
# Assassinate Unified Test Runner
# =============================================================================
# Consolidates all testing into one script that mirrors CI behavior.
#
# Usage:
#   ./scripts/test.sh <command> [options]
#
# Commands:
#   local           Run tests locally with uv (fast, no Docker)
#   docker          Run full integration tests in Docker
#   distro [options] <name>   Test specific distro (ubuntu, debian, fedora, alpine, arch, kali, parrot)
#   matrix          Run all distros (simulates CI matrix)
#   ci              Full CI simulation (lint + matrix + integration)
#   build           Build all Docker images
#   clean           Clean up Docker resources
#
# Options:
#   -v, --verbose   Verbose output
#   -f, --full      Full provisioning (for distro tests)
#   -h, --help      Show this help
#
# Examples:
#   ./scripts/test.sh local                    # Quick local tests
#   ./scripts/test.sh docker                   # Full integration in Docker
#   ./scripts/test.sh distro ubuntu            # Test Ubuntu distro (recon only)
#   ./scripts/test.sh distro --full kali       # Full provisioning on Kali
#   ./scripts/test.sh distro --full ubuntu     # Full provisioning + build on Ubuntu
#   ./scripts/test.sh matrix                   # Test all distros
#   ./scripts/test.sh ci                       # Full CI simulation
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${PROJECT_ROOT}/docker"
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.yml"

# Available distros (matching CI matrix)
DISTROS=(ubuntu debian fedora alpine arch)
SECURITY_DISTROS=(kali parrot)
ALL_DISTROS=("${DISTROS[@]}" "${SECURITY_DISTROS[@]}")

# Options
VERBOSE=false
FULL_PROVISION=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

log_info()    { echo -e "${BLUE}[INFO]${RESET} $*"; }
log_success() { echo -e "${GREEN}[✓]${RESET} $*"; }
log_error()   { echo -e "${RED}[✗]${RESET} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }

log_header() {
    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  $*${RESET}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

show_help() {
    head -30 "$0" | tail -27 | sed 's/^# //' | sed 's/^#//'
    exit 0
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
}

compose() {
    docker compose -f "${COMPOSE_FILE}" "$@"
}

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------

cmd_local() {
    log_header "Running Local Tests"
    cd "${PROJECT_ROOT}"

    # Check for uv
    if ! command -v uv &> /dev/null; then
        log_error "uv is not installed. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi

    # Run linting
    log_info "Running linting..."
    uv run ruff check python/ setup/ || true
    uv run ruff format --check python/ setup/ || true

    # Run type checking
    log_info "Running type checks..."
    uv run mypy python/assassinate/ --ignore-missing-imports || true

    # Run tests
    log_info "Running pytest..."
    if [[ "$VERBOSE" == "true" ]]; then
        uv run pytest tests/ -v --tb=short
    else
        uv run pytest tests/ --tb=short -q
    fi

    log_success "Local tests passed!"
}

cmd_docker() {
    log_header "Running Docker Integration Tests"
    check_docker
    cd "${PROJECT_ROOT}"

    # Build if needed
    log_info "Building integration test image..."
    compose build integration-test

    # Start postgres and run tests
    log_info "Starting PostgreSQL..."
    compose up -d postgres

    log_info "Waiting for PostgreSQL to be healthy..."
    sleep 5

    log_info "Running integration tests..."
    if compose run --rm integration-test; then
        log_success "Integration tests passed!"
        compose down -v
    else
        log_error "Integration tests failed"
        compose down -v
        exit 1
    fi
}

cmd_distro() {
    local distro="${1:-}"

    if [[ -z "$distro" ]]; then
        log_error "No distro specified"
        log_info "Available: ${ALL_DISTROS[*]}"
        exit 1
    fi

    # Validate distro
    local valid=false
    for d in "${ALL_DISTROS[@]}"; do
        if [[ "$d" == "$distro" ]]; then
            valid=true
            break
        fi
    done

    if [[ "$valid" == "false" ]]; then
        log_error "Invalid distro: $distro"
        log_info "Available: ${ALL_DISTROS[*]}"
        exit 1
    fi

    log_header "Testing Distro: ${distro}"
    check_docker
    cd "${PROJECT_ROOT}"

    # Build image
    log_info "Building ${distro} image..."
    compose build "$distro" 2>/dev/null || true

    # Run test
    local run_args=(run --rm)
    local cmd_args=()

    if [[ "$FULL_PROVISION" == "true" ]]; then
        log_info "Running full installation (as root)..."
        run_args+=(--user root)

        # Use unified ansible-based installer for all distros
        cmd_args=(bash -l -c "cd /home/hitman/assassinate && .venv/bin/assassinate-setup --install --skip-steps msf -v")
    else
        log_info "Running reconnaissance check..."
        # Use unified recon-only for all distros
        cmd_args=(bash -l -c "cd /home/hitman/assassinate && .venv/bin/assassinate-setup --recon-only")
    fi

    # Run with profile
    if [[ ${#cmd_args[@]} -gt 0 ]]; then
        if compose "${run_args[@]}" "$distro" "${cmd_args[@]}"; then
            log_success "${distro} test passed!"
        else
            log_error "${distro} test failed"
            exit 1
        fi
    else
        if compose "${run_args[@]}" "$distro"; then
            log_success "${distro} test passed!"
        else
            log_error "${distro} test failed"
            exit 1
        fi
    fi
}

cmd_matrix() {
    log_header "Running Distro Matrix (CI Simulation)"
    check_docker
    cd "${PROJECT_ROOT}"

    local failed=0
    local passed=0
    local results=()

    # Build all images first
    log_info "Building all distro images..."
    for distro in "${DISTROS[@]}"; do
        log_info "Building ${distro}..."
        compose build "$distro" 2>/dev/null || true
    done

    # Run tests
    for distro in "${DISTROS[@]}"; do
        echo ""
        log_info "Testing ${BOLD}${distro}${RESET}..."

        if compose run --rm "$distro"; then
            log_success "${distro} passed"
            results+=("${distro}:PASS")
            ((passed++))
        else
            log_error "${distro} failed"
            results+=("${distro}:FAIL")
            ((failed++))
        fi
    done

    # Summary
    log_header "Matrix Results"
    echo -e "${BOLD}Distro          Result${RESET}"
    echo "────────────────────────"
    for result in "${results[@]}"; do
        distro="${result%:*}"
        status="${result#*:}"
        if [[ "$status" == "PASS" ]]; then
            echo -e "${distro}\t\t${GREEN}${status}${RESET}"
        else
            echo -e "${distro}\t\t${RED}${status}${RESET}"
        fi
    done
    echo "────────────────────────"
    echo -e "${BOLD}Total: ${passed}/$((passed + failed)) passed${RESET}"

    if [[ $failed -gt 0 ]]; then
        exit 1
    fi
}

cmd_ci() {
    log_header "Full CI Simulation"

    local start_time=$(date +%s)

    # Step 1: Local lint checks
    log_info "Step 1/3: Linting..."
    cd "${PROJECT_ROOT}"
    uv run ruff check python/ setup/ --fix || true
    uv run ruff format python/ setup/ || true

    # Step 2: Distro matrix
    log_info "Step 2/3: Distro matrix..."
    cmd_matrix

    # Step 3: Integration tests
    log_info "Step 3/3: Integration tests..."
    cmd_docker

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_header "CI Simulation Complete"
    log_success "All checks passed in ${duration}s"
}

cmd_build() {
    log_header "Building All Docker Images"
    check_docker
    cd "${PROJECT_ROOT}"

    log_info "Building integration test image..."
    compose build integration-test

    log_info "Building distro images..."
    for distro in "${DISTROS[@]}"; do
        log_info "Building ${distro}..."
        compose build "$distro"
    done

    log_success "All images built!"
}

cmd_clean() {
    log_header "Cleaning Docker Resources"
    check_docker
    cd "${PROJECT_ROOT}"

    log_info "Stopping containers..."
    compose down -v 2>/dev/null || true

    log_info "Removing images..."
    for distro in "${ALL_DISTROS[@]}"; do
        docker rmi "assassinate-${distro}" 2>/dev/null || true
    done
    docker rmi "docker-integration-test" 2>/dev/null || true

    log_info "Pruning..."
    docker image prune -f
    docker volume prune -f

    log_success "Cleanup complete!"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    local command="${1:-}"
    shift || true

    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--full)
                FULL_PROVISION=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                break
                ;;
        esac
    done

    case "$command" in
        local)
            cmd_local
            ;;
        docker)
            cmd_docker
            ;;
        distro)
            cmd_distro "$@"
            ;;
        matrix)
            cmd_matrix
            ;;
        ci)
            cmd_ci
            ;;
        build)
            cmd_build
            ;;
        clean)
            cmd_clean
            ;;
        -h|--help|help|"")
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            ;;
    esac
}

main "$@"
