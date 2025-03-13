#!/usr/bin/env python3
"""
Evrmore Accounts API Server Runner

This script runs the Evrmore Accounts API server with proper error handling
and configuration options.

Usage:
    python3 run.py [--host HOST] [--port PORT] [--debug]

Options:
    --host HOST    Host to bind to (default: 0.0.0.0)
    --port PORT    Port to bind to (default: 5000)
    --debug        Enable debug mode
"""
import os
import sys
import argparse
import logging
from evrmore_accounts.app import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("evrmore_accounts_runner")

def main():
    """Main entry point for the server runner"""
    parser = argparse.ArgumentParser(description="Evrmore Accounts API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Configure Flask environment
    os.environ["FLASK_ENV"] = "development" if args.debug else "production"
    os.environ["DEBUG"] = "true" if args.debug else "false"
    
    try:
        # Create and run the Flask application
        app = create_app()
        
        print("=" * 80)
        print("EVRMORE ACCOUNTS API SERVER")
        print("=" * 80)
        print(f"Server running at: http://{args.host}:{args.port}")
        print(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
        print("Press Ctrl+C to stop the server")
        print("=" * 80)
        
        app.run(host=args.host, port=args.port, debug=args.debug)
        return 0
        
    except Exception as e:
        logger.error(f"Error starting server: {e}", exc_info=True)
        print(f"Error starting server: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 