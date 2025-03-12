#!/usr/bin/env python3
"""
WSGI entry point for the Evrmore Accounts application.
This file is used to run the application with Gunicorn.
"""
import os
from evrmore_accounts.app import create_app

# Create the Flask application
application = create_app()

# Make the application available as 'app' for some WSGI servers
app = application

if __name__ == "__main__":
    # Get port from environment or use default
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")
    
    # Run the app
    app.run(host=host, port=port) 