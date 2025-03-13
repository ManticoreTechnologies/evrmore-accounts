#!/usr/bin/env python3
"""
Evrmore Accounts API

This module provides the RESTful API for the Evrmore Accounts service.
It creates a Flask Blueprint for API endpoints and exports it for use in applications.
This is a pure REST API with no frontend components.
"""
from flask import Blueprint

from evrmore_accounts.api.server import AccountsServer
from evrmore_accounts.api.auth import auth_bp

# Create a Blueprint for API endpoints
api_bp = Blueprint("api", __name__)

# Register the auth blueprint directly
api_bp.register_blueprint(auth_bp, url_prefix='/auth')

# Create server instance for the app to use
def create_server(debug=False):
    """Create a new AccountsServer instance.
    
    Args:
        debug: Enable debug mode
        
    Returns:
        AccountsServer: A new server instance for REST API
    """
    return AccountsServer(debug=debug) 