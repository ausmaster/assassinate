#!/bin/bash
# Run all tests in Docker environment
# Ensures clean, reproducible test execution

set -e

echo "=========================================================================="
echo "Assassinate Docker Test Runner"
echo "=========================================================================="
echo ""

# Parse arguments
REBUILD=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --rebuild)
            REBUILD=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --rebuild    Rebuild Docker images from scratch"
            echo "  --verbose    Show detailed test output"
            echo "  --help       Show this help message"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running"
    echo "Please start Docker and try again"
    exit 1
fi

# Clean up old containers
echo "Cleaning up old containers..."
docker-compose -f docker-compose.test.yml down -v 2>/dev/null || true

# Build images
if [ "$REBUILD" = true ]; then
    echo ""
    echo "Rebuilding Docker images from scratch..."
    docker-compose -f docker-compose.test.yml build --no-cache
else
    echo ""
    echo "Building Docker images..."
    docker-compose -f docker-compose.test.yml build
fi

# Run tests
echo ""
echo "=========================================================================="
echo "Running tests in Docker container..."
echo "=========================================================================="
echo ""

if [ "$VERBOSE" = true ]; then
    docker-compose -f docker-compose.test.yml run --rm assassinate-test
else
    docker-compose -f docker-compose.test.yml run --rm assassinate-test | grep -E "(PASSED|FAILED|ERROR|===)"
fi

TEST_EXIT_CODE=${PIPESTATUS[0]}

# Cleanup
echo ""
echo "Cleaning up..."
docker-compose -f docker-compose.test.yml down -v

# Report results
echo ""
echo "=========================================================================="
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✓ All tests passed in Docker environment!"
    echo "=========================================================================="
    exit 0
else
    echo "✗ Tests failed in Docker environment"
    echo "=========================================================================="
    echo ""
    echo "To debug, run with --verbose flag:"
    echo "  $0 --verbose"
    exit 1
fi
