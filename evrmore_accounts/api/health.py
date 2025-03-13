#!/usr/bin/env python3
"""
Evrmore Accounts Health Check API

This module provides a health check endpoint to verify the API's operational status.
"""
import os
import platform
import sqlite3
import logging
from flask import Blueprint, jsonify, current_app, request
from sqlalchemy import text

# Create blueprint
health_blueprint = Blueprint('health', __name__)

# Configure logging
logger = logging.getLogger("evrmore_accounts.health")

@health_blueprint.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify the API is running
    
    Returns:
        JSON response with API status
    """
    # Check for reset request (for testing only)
    if 'reset' in request.args and current_app.config.get('TESTING', False):
        # Reset rate limiter state if we're in testing mode
        if hasattr(current_app, 'security'):
            rate_limiter = current_app.security.get("rate_limiter")
            if rate_limiter:
                # Clear all request counts
                rate_limiter.requests = {}
                rate_limiter.blocked_requests = 0
                logger.info("Rate limiter state reset for testing")
    
    # Check database connection
    db_status = "ok"
    db_error = None
    
    try:
        # Verify database exists and is accessible
        from evrmore_accounts.database import DB_PATH, engine
        
        if not os.path.exists(DB_PATH):
            db_status = "error"
            db_error = "Database file not found"
        else:
            # Try a simple query
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = "error"
        db_error = str(e)
        logger.error(f"Database health check failed: {e}")
    
    # Prepare response
    response = {
        "status": "ok" if db_status == "ok" else "error",
        "service": "evrmore-accounts",
        "version": "1.0.0",
        "timestamp": None,  # Will be added by the security middleware
        "database": {
            "status": db_status
        },
        "system": {
            "python": platform.python_version(),
            "platform": platform.platform()
        }
    }
    
    # Add error details if any
    if db_error:
        response["database"]["error"] = db_error
    
    # Log health check
    if response["status"] == "ok":
        logger.info("Health check passed")
    else:
        logger.warning(f"Health check failed: {response}")
    
    return jsonify(response) 