#!/bin/bash
# Unified logging demonstration - Both Python and Rust logs to files
# This shows how to capture all logs from both components

set -e

# Configuration
PYTHON_LOG_FILE="/tmp/assassinate_python.log"
RUST_LOG_FILE="/tmp/assassinate_rust.log"
LOG_LEVEL="DEBUG"

echo "=========================================================================="
echo "Unified Logging Demonstration - Python + Rust to Files"
echo "=========================================================================="
echo ""
echo "Configuration:"
echo "  Python logs → $PYTHON_LOG_FILE"
echo "  Rust logs   → $RUST_LOG_FILE"
echo "  Log level   → $LOG_LEVEL"
echo ""

# Clean up old logs
rm -f "$PYTHON_LOG_FILE" "$RUST_LOG_FILE"

# Kill any existing daemon
pkill -f "rust/daemon" 2>/dev/null || true
sleep 1

# Start Rust daemon with DEBUG logging to file
echo "1. Starting Rust daemon with file logging..."
./rust/daemon/target/release/daemon \
    --msf-root /home/aus/PycharmProjects/assassinate/metasploit-framework \
    --log-level debug \
    > "$RUST_LOG_FILE" 2>&1 &

DAEMON_PID=$!
echo "   Daemon started with PID: $DAEMON_PID"
echo ""

# Wait for daemon to initialize
sleep 5

# Run Python client with file logging
echo "2. Running Python client with file logging..."
ASSASSINATE_LOG_LEVEL="$LOG_LEVEL" \
ASSASSINATE_LOG_FILE="$PYTHON_LOG_FILE" \
uv run python3 << 'PYTHON_SCRIPT'
import asyncio
from assassinate.ipc.client import MsfClient

async def main():
    print("   Making RPC calls...")
    async with MsfClient() as client:
        # Call 1: Get version
        version = await client.framework_version()
        print(f"   ✓ framework_version: {version['version']}")

        # Call 2: List modules
        exploits = await client.list_modules("exploit")
        print(f"   ✓ list_modules: {len(exploits)} exploits")

        # Call 3: Search
        results = await client.search("vsftpd")
        print(f"   ✓ search: {len(results)} results")

        # Call 4: Create module
        if results:
            module_id = await client.create_module(results[0])
            print(f"   ✓ create_module: {module_id}")

            # Call 5: Get module info
            info = await client.module_info(module_id)
            print(f"   ✓ module_info: {info['name']}")

            # Call 6: Delete module
            await client.delete_module(module_id)
            print(f"   ✓ delete_module: done")

asyncio.run(main())
PYTHON_SCRIPT

echo ""

# Stop daemon
echo "3. Stopping daemon..."
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
echo ""

# Show statistics
echo "=========================================================================="
echo "Log File Statistics:"
echo "=========================================================================="
echo ""
echo "Python log ($PYTHON_LOG_FILE):"
echo "  Lines: $(wc -l < "$PYTHON_LOG_FILE")"
echo "  Size:  $(du -h "$PYTHON_LOG_FILE" | cut -f1)"
echo ""
echo "Rust log ($RUST_LOG_FILE):"
echo "  Lines: $(wc -l < "$RUST_LOG_FILE")"
echo "  Size:  $(du -h "$RUST_LOG_FILE" | cut -f1)"
echo ""

# Show sample of Python logs
echo "=========================================================================="
echo "Sample Python Logs (last 20 lines):"
echo "=========================================================================="
tail -20 "$PYTHON_LOG_FILE"
echo ""

# Show sample of Rust logs
echo "=========================================================================="
echo "Sample Rust Logs (DEBUG entries only):"
echo "=========================================================================="
grep DEBUG "$RUST_LOG_FILE" | tail -20
echo ""

# Show correlated logs for a specific call
echo "=========================================================================="
echo "Correlated Logs Example (call_id=3 - search):"
echo "=========================================================================="
echo ""
echo "Python side:"
grep "\[3\]" "$PYTHON_LOG_FILE" | head -5
echo ""
echo "Rust side:"
grep "call_id=3" "$RUST_LOG_FILE"
echo ""

echo "=========================================================================="
echo "Complete logs available at:"
echo "  Python: $PYTHON_LOG_FILE"
echo "  Rust:   $RUST_LOG_FILE"
echo "=========================================================================="
echo ""
echo "Tip: Use 'tail -f' to watch logs in real-time:"
echo "  tail -f $PYTHON_LOG_FILE &"
echo "  tail -f $RUST_LOG_FILE &"
echo ""
