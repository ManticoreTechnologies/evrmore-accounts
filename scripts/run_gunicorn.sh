#!/bin/bash
# Evrmore Accounts - Gunicorn Production Server Runner
# This script runs the Evrmore Accounts API with Gunicorn for production

# Default configuration
HOST=${HOST:-"0.0.0.0"}
PORT=${PORT:-"8000"}
WORKERS=${WORKERS:-4}
TIMEOUT=${TIMEOUT:-120}
WORKER_CLASS=${WORKER_CLASS:-"gevent"}
LOG_LEVEL=${LOG_LEVEL:-"info"}

echo "===================================================="
echo "EVRMORE ACCOUNTS API PRODUCTION SERVER"
echo "===================================================="
echo "Starting server with Gunicorn"
echo "Host: $HOST"
echo "Port: $PORT"
echo "Workers: $WORKERS"
echo "Timeout: $TIMEOUT seconds"
echo "Worker Class: $WORKER_CLASS"
echo "Log Level: $LOG_LEVEL"
echo "===================================================="

# Change to the project root directory
cd "$(dirname "$0")/.." || exit 1

# Launch Gunicorn with the configured settings
exec gunicorn "evrmore_accounts.app:create_app()" \
    --bind $HOST:$PORT \
    --workers $WORKERS \
    --timeout $TIMEOUT \
    --worker-class $WORKER_CLASS \
    --log-level $LOG_LEVEL \
    --access-logfile - \
    --error-logfile - 