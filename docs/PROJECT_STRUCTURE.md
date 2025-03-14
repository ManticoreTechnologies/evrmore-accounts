# Evrmore Accounts Project Structure

This document provides an overview of the Evrmore Accounts project structure and organization.

## Directory Structure

```
evrmore-accounts/
│── evrmore_accounts/     # Main package (source code)
│   ├── __init__.py       # Package initialization
│   ├── app.py            # Main entry point
│   ├── api/              # API endpoints
│   │   ├── auth.py       # Authentication endpoints
│   │   ├── user.py       # User management endpoints
│   │   ├── health.py     # Health check endpoints
│   │   └── twofa.py      # Two-factor authentication endpoints
│   ├── database.py       # Database models & management
│   ├── server_security.py # Security & rate-limiting features
│   ├── healthcheck.py    # Health check utilities
│   ├── advanced_rate_limiter.py # Rate limiting implementation
│   ├── security_headers.py # Security headers middleware
│   └── data/             # Data files
│
│── config/               # Configuration files
│   ├── config.py         # Configuration classes
│   └── .env.example      # Example environment variables
│
│── tests/                # Test files
│   ├── unit/             # Unit tests for individual components
│   │   └── db_test.py    # Database unit tests
│   ├── integration/      # Integration tests for component interactions
│   │   └── test_backend.py # Backend API integration tests
│   └── security/         # Security-focused tests
│       └── test_security.py # Security tests
│
│── docs/                 # Documentation
│   ├── implementation/   # Implementation documentation
│   ├── implementation_plan.md # Implementation plan
│   ├── project_summary.md # Project summary
│   ├── security_audit_report.md # Security audit report
│   ├── security_implementation_guide.md # Security implementation guide
│   └── SECURITY.md       # Security documentation
│
│── scripts/              # Helper scripts
│   ├── run.py            # Development server runner
│   ├── run_gunicorn.sh   # Production server runner
│   └── init_db.py        # Database initialization script
│
│── instance/             # Instance-specific data
│   └── evrmore_accounts.db # SQLite database file
│
│── frontend/             # Frontend-related files (if any)
│
│── setup.py              # Package setup script
│── setup.cfg             # Package configuration
│── pyproject.toml        # Project configuration
│── MANIFEST.in           # Package manifest
│── Makefile              # Build automation
│── wsgi.py               # WSGI entry point
└── LICENSE               # License file
```

## Key Components

1. **API Layer** (`evrmore_accounts/api/`): Contains all the API endpoints and controllers.
   - `auth.py`: Authentication endpoints (challenge, authenticate, validate, logout)
   - `user.py`: User profile management
   - `twofa.py`: Two-factor authentication
   - `health.py`: Health check and monitoring

2. **Data Layer** (`evrmore_accounts/database.py`): Defines the data models and database access.
   - User model
   - Session tracking
   - Two-factor authentication settings
   - Challenge management

3. **Security Components** (`evrmore_accounts/server_security.py` and others):
   - Rate limiting
   - Security headers
   - Session management
   - JWT token handling

4. **Configuration** (`config/`): Application configuration management.
   - Environment-specific settings (development, testing, production)
   - Security settings
   - Database settings

5. **Testing** (`tests/`): Comprehensive test suite.
   - Unit tests for individual components
   - Integration tests for API functionality
   - Security-focused tests for security features

6. **Utilities** (`scripts/`): Helper scripts for development and deployment.
   - Development server runner
   - Production server with Gunicorn
   - Database initialization

## Build and Deployment

The project includes several tools for building, testing, and deployment:

- **Makefile**: Provides common commands for development and testing.
- **setup.py**: Package installation configuration.
- **pyproject.toml**: Modern Python packaging configuration.
- **MANIFEST.in**: Package file inclusion rules.
- **wsgi.py**: WSGI entry point for production servers.

## Documentation

The `docs/` directory contains comprehensive documentation:

- Implementation details
- API references
- Security documentation
- Project planning and summaries 