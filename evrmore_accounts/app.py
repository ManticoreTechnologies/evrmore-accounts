#!/usr/bin/env python3
"""
Evrmore Accounts Application

This module provides a Flask application that serves both the API endpoints
and a web interface for the Evrmore Accounts service.
"""
import os
import logging
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from flask import Flask, render_template, send_from_directory, url_for

from evrmore_accounts.api import AccountsServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("evrmore_accounts.app")

# Load environment variables
load_dotenv()

# Get debug mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "t", "yes")


class EvrmoreAccountsApp:
    """Flask application for Evrmore Accounts."""

    def __init__(self, debug: bool = DEBUG):
        """Initialize the application.

        Args:
            debug: Enable debug mode
        """
        self.debug = debug
        logger.info(f"Initializing Evrmore Accounts App (debug={debug})")

        # Initialize API server
        self.accounts_server = AccountsServer(debug=debug)

        # Get package root directory
        self.package_dir = Path(__file__).parent
        self.root_dir = self.package_dir.parent
        
        # Create Flask app
        self.app = Flask(
            __name__,
            static_folder=str(self.package_dir / "static"),
            template_folder=str(self.package_dir / "templates")
        )
        self.app.config["DEBUG"] = debug
        self.app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key")
        
        # Use the API server's Flask app routes
        api_app = self.accounts_server.get_app()
        
        # Copy all routes from the API app to our main app
        for rule in api_app.url_map.iter_rules():
            if rule.endpoint != 'static' and rule.endpoint in api_app.view_functions:
                view_func = api_app.view_functions[rule.endpoint]
                
                # Register the route with our app
                self.app.add_url_rule(
                    rule.rule,
                    endpoint=rule.endpoint,
                    view_func=view_func,
                    methods=rule.methods
                )
        
        # Register web routes
        self._register_web_routes()
        
        logger.info("Evrmore Accounts App initialized")

    def _register_web_routes(self):
        """Register web routes with the Flask app."""
        
        @self.app.route("/")
        def index():
            """Render the index page."""
            return render_template("index.html")
        
        @self.app.route("/demo")
        def demo():
            """Render the demo page."""
            return render_template("example.html")
        
        @self.app.route("/example")
        def example():
            """Render the simple integration example page."""
            example_path = self.root_dir / "simple_integration_example.html"
            if example_path.exists():
                with open(example_path, 'r') as f:
                    content = f.read()
                return content
            else:
                return render_template("example.html")
        
        @self.app.route("/static/<path:path>")
        def serve_static(path):
            """Serve static files."""
            return send_from_directory(self.app.static_folder, path)
        
        @self.app.route("/docs")
        def docs():
            """Render the documentation page."""
            return render_template("docs.html")
        
        @self.app.route("/integration")
        def integration():
            """Render the integration guide page."""
            return render_template("integration.html")
        
        @self.app.route("/admin")
        def admin():
            """Render the admin dashboard page."""
            return render_template("admin.html")
        
        @self.app.context_processor
        def inject_urls():
            """Inject URLs into templates."""
            return {
                'url_for_static': lambda filename: url_for('serve_static', path=filename)
            }

    def run(self, host: str = "0.0.0.0", port: int = 5000):
        """Run the application.

        Args:
            host: Host to bind to
            port: Port to run on
        """
        logger.info(f"Starting Evrmore Accounts App on {host}:{port}")
        self.app.run(host=host, port=port, debug=self.debug)

    def get_app(self) -> Flask:
        """Get the Flask application.

        Returns:
            Flask application
        """
        return self.app


def create_app(debug: bool = DEBUG) -> Flask:
    """Create a new Flask application.

    Args:
        debug: Enable debug mode

    Returns:
        Flask application
    """
    return EvrmoreAccountsApp(debug=debug).get_app()


if __name__ == "__main__":
    # Get port from environment or use default
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")
    
    # Create and run app
    app = EvrmoreAccountsApp(debug=DEBUG)
    app.run(host=host, port=port) 