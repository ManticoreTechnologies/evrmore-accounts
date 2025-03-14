#!/usr/bin/env python3
"""
Database Initialization Script for Evrmore Accounts

This script initializes the database with the required tables.
It can be used to create a new database or reset an existing one.
"""
import os
import sys
import logging
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("evrmore_accounts.init_db")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Initialize the Evrmore Accounts database")
    parser.add_argument("--reset", action="store_true", help="Reset the database if it exists")
    args = parser.parse_args()
    
    # Add the project root to the path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    
    try:
        from evrmore_accounts.database import init_db, DB_PATH
        
        if args.reset and os.path.exists(DB_PATH):
            logger.info(f"Removing existing database: {DB_PATH}")
            os.remove(DB_PATH)
        
        # Create database directory if it doesn't exist
        db_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(db_dir):
            logger.info(f"Creating directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)
        
        # Initialize the database
        logger.info(f"Initializing database at: {DB_PATH}")
        init_db()
        
        logger.info("Database initialization complete")
        return 0
    
    except Exception as e:
        logger.error(f"Error initializing database: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main()) 