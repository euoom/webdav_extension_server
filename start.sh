#!/bin/bash

# Check if a server.pid file exists
if [ -f "server.pid" ]; then
    PID=$(cat server.pid)
    # Check if a process with that PID is actually running
    if ps -p $PID > /dev/null; then
        echo "Server is already running with PID: $PID. Exiting."
        exit 0
    else
        # The PID file exists, but the process is not running.
        # This is a stale file, so we should remove it.
        echo "Stale server.pid file found. Removing it."
        rm server.pid
    fi
fi

echo "Starting server..."

# Run the server in the background with nohup.
# Redirect stdout and stderr to server.log
nohup uv run main.py > server.log 2>&1 &

# Save the process ID (PID) to a file
echo $! > server.pid

echo "Server started with PID: $(cat server.pid)"
echo "Logs are being written to server.log"

