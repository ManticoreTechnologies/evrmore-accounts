#!/usr/bin/env python3
"""
Evrmore Accounts API

This module provides the RESTful API for the Evrmore Accounts service.
It creates a Flask Blueprint for API endpoints and exports it for use in applications.
"""
from flask import Blueprint

from evrmore_accounts.api.server import AccountsServer

# Create a Blueprint for API endpoints
api_bp = Blueprint("api", __name__)

# Create a server instance to register routes
server = AccountsServer()

# Get the app and extract the registered routes
app = server.get_app()

# Register routes from the server to the Blueprint
for rule in app.url_map.iter_rules():
    if rule.endpoint != 'static' and hasattr(app.view_functions, rule.endpoint):
        # Copy the view function to the blueprint
        view_func = app.view_functions[rule.endpoint]
        
        # Register the route with the blueprint
        api_bp.add_url_rule(
            rule.rule,
            endpoint=rule.endpoint,
            view_func=view_func,
            methods=rule.methods
        ) 