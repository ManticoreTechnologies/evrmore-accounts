#!/usr/bin/env python3
"""
Evrmore Accounts Development Server Runner

This script runs the Evrmore Accounts API in development mode.

Usage:
    python3 scripts/run.py [--host HOST] [--port PORT] [--debug]

Options:
    --host HOST     Host to bind to (default: 0.0.0.0)
    --port PORT     Port to bind to (default: 5000)
    --debug         Enable debug mode
"""
import os
import sys
import argparse

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

def main():
    """Main entry point for the development server"""
    parser = argparse.ArgumentParser(description="Run the Evrmore Accounts API development server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", default=5000, type=int, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Set environment variables
    os.environ["HOST"] = args.host
    os.environ["PORT"] = str(args.port)
    os.environ["DEBUG"] = "true" if args.debug else "false"
    
    # Import and run the app
    from evrmore_accounts.app import create_app
    
    app = create_app()
    app.run(debug=args.debug, host=args.host, port=args.port)

if __name__ == "__main__":
    main() 