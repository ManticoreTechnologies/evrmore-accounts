#!/usr/bin/env python3
"""
Evrmore Accounts - Database Test Script

This script tests the database connection and initializes the database if needed.
It helps diagnose any issues with the database configuration.
"""
import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("db_test")

def main():
    """Main entry point"""
    print("Testing database connection...")
    
    try:
        # Add the project root to the Python path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Import database module
        from evrmore_accounts.database import init_db, engine, DB_PATH
        from sqlalchemy import text
        
        # Check if database directory exists
        db_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(db_dir):
            print(f"Creating directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)
        
        # Initialize database
        print(f"Database path: {DB_PATH}")
        init_db()
        
        # Test connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            for row in result:
                print(f"Connection test result: {row[0]}")
        
        print("Database connection successful!")
        return 0
        
    except Exception as e:
        logger.error(f"Error connecting to database: {e}", exc_info=True)
        print(f"Database connection failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 