# Evrmore Accounts

<div align="center">
  <img src="evrmore_accounts/static/evrmore-logo.svg" alt="Evrmore Accounts" width="250">
  <h1>Evrmore Accounts</h1>
  
  <p>A secure wallet-based authentication system for Evrmore blockchain applications</p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
</div>

## Overview

Evrmore Accounts is a Python package that provides wallet-based authentication using Evrmore blockchain. It builds on the [Evrmore Authentication](https://github.com/manticoretechnologies/evrmore-authentication) library to provide a complete account management system for web applications.

## Features

- **🔑 Wallet-based authentication** - Users sign challenges with their Evrmore wallet
- **🔒 JWT token management** - Secure session handling with JSON Web Tokens
- **📁 SQLite backend** - Simple, file-based database for session and challenge storage
- **👤 Automatic user management** - Users are created on first authentication
- **🌐 Complete API server** - Ready-to-use API server for authentication endpoints
- **🖥️ Demo web interface** - Example application showing the complete authentication flow
- **📱 JavaScript client library** - Easy integration with web applications

## Installation

```bash
pip3 install evrmore-accounts
```

## Quick Start

### Running the API Server (Development)

```bash
python3 -m evrmore_accounts.app
```

This will start a Flask application with both the API endpoints and a web interface available at http://localhost:5000.

### Running with Gunicorn (Production)

For production deployments, we recommend using Gunicorn:

```bash
# Basic usage
gunicorn --bind 0.0.0.0:5000 --workers 4 wsgi:app

# Or use the provided script
./run_gunicorn.sh
```

You can customize the configuration by setting environment variables:

```bash
# Custom configuration
export PORT=8000
export WORKERS=2
export TIMEOUT=60
export JWT_SECRET=your_secure_secret_key

# Run with custom configuration
./run_gunicorn.sh
```

For more details, see the [Deployment Guide](docs/guide/deployment.md).

### Docker Deployment

```bash
# Build the Docker image
docker build -t evrmore-accounts .

# Run the container
docker run -p 5000:5000 evrmore-accounts
```

### Running the Demo

Open `http://localhost:5000/demo` in your web browser to see the authentication flow in action.

### Integration Example

Check out the `simple_integration_example.html` file for an example of how to integrate Evrmore Accounts with your web application.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/challenge` | POST | Generate a challenge for a user |
| `/api/authenticate` | POST | Authenticate with a signed challenge |
| `/api/validate` | GET | Validate a JWT token |
| `/api/user` | GET | Get authenticated user information |
| `/api/logout` | POST | Invalidate a JWT token (logout) |

## JavaScript Library

Add the Evrmore Accounts JavaScript library to your web application:

```html
<script src="https://cdn.manticore.technology/static/evrmore-accounts.js"></script>
```

Initialize the library and create a sign-in button:

```javascript
// Initialize Evrmore Accounts
EvrmoreAccounts.init({
  apiUrl: 'https://auth.manticore.technology/api',
  autoRefresh: true,
  debug: false
});

// Create a sign-in button
EvrmoreAccounts.initSignInButton('#sign-in-button');

// Listen for authentication state changes
EvrmoreAccounts.onAuthStateChanged(function(user) {
  if (user) {
    console.log('User is signed in:', user);
    // Show authenticated UI
  } else {
    console.log('User is signed out');
    // Show sign-in UI
  }
});
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/manticoretechnologies/evrmore-accounts.git
cd evrmore-accounts

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install -e .
```

### Running Tests

```bash
python3 test_evrmore_accounts.py
```

## Documentation

For comprehensive documentation, visit [our documentation site](https://manticoretechnologies.github.io/evrmore-accounts/).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- Website: [manticore.technology](https://manticore.technology)
- GitHub: [github.com/manticoretechnologies](https://github.com/manticoretechnologies)
- Email: [dev@manticore.technology](mailto:dev@manticore.technology) 