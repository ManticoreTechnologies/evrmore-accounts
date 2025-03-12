#!/bin/bash
# Script to run Evrmore Accounts with Gunicorn

# Get environment variables or set defaults
PORT=${PORT:-5000}
HOST=${HOST:-0.0.0.0}
WORKERS=${WORKERS:-4}
TIMEOUT=${TIMEOUT:-120}
LOG_LEVEL=${LOG_LEVEL:-info}

# Ensure Python environment is activated if using a virtual environment
# source venv/bin/activate

echo "Starting Evrmore Accounts with Gunicorn on $HOST:$PORT with $WORKERS workers..."

# Run Gunicorn
exec gunicorn --bind $HOST:$PORT \
              --workers $WORKERS \
              --timeout $TIMEOUT \
              --log-level $LOG_LEVEL \
              --access-logfile - \
              --error-logfile - \
              "wsgi:app" 