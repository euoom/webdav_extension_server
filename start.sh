#!/bin/bash

echo "Starting server..."

# Run the server in the background with nohup.
# Redirect stdout and stderr to .server.log
nohup uv run main.py > .server.log 2>&1 &

# Save the process ID (PID) to a file
echo $! > .server.pid

echo "Server started with PID: $(cat .server.pid)"
echo "Logs are being written to .server.log"
