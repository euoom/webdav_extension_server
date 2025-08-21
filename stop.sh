#!/bin/bash

echo "Stopping server..."

if [ ! -f .server.pid ]; then
    echo "PID file not found. Is the server running?"
    exit 1
fi

PID=$(cat server.pid)
kill $PID

# Wait a moment to see if the process terminates gracefully
sleep 2

# Check if the process is still running and force kill if necessary
if ps -p $PID > /dev/null; then
   echo "Server process $PID did not stop gracefully. Sending SIGKILL..."
   kill -9 $PID
fi

rm .server.pid
echo "Server stopped."
