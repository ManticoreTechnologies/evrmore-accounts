# Configuration

This page explains how to configure Evrmore Accounts for your specific needs.

## Environment Variables

Evrmore Accounts can be configured using environment variables. You can set these in your environment or use a `.env` file in your project directory.

### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port to run the server on | `5000` |
| `HOST` | Host to bind to | `0.0.0.0` |
| `DEBUG` | Enable debug mode | `false` |
| `SECRET_KEY` | Secret key for JWT token signing | `dev-key` (change in production!) |

### Database Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection URL | `sqlite:///evrmore_accounts.db` |

### Authentication Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CHALLENGE_EXPIRE_MINUTES` | Minutes until a challenge expires | `10` |
| `TOKEN_EXPIRE_DAYS` | Days until a JWT token expires | `7` |
| `EVRMORE_AUTH_DEBUG` | Enable debug mode for Evrmore Authentication | `false` |

## Example .env File

```
# Server configuration
PORT=5000
HOST=0.0.0.0
DEBUG=false
SECRET_KEY=your-secret-key-here

# Database configuration
DATABASE_URL=sqlite:///evrmore_accounts.db

# Authentication configuration
CHALLENGE_EXPIRE_MINUTES=10
TOKEN_EXPIRE_DAYS=7
EVRMORE_AUTH_DEBUG=false
```

## Configuration in Code

You can also configure Evrmore Accounts programmatically when creating the application:

```python
from evrmore_accounts.app import EvrmoreAccountsApp

# Create app with custom configuration
app = EvrmoreAccountsApp(debug=True)

# Run the app on a custom port
app.run(host="127.0.0.1", port=8000)
```

## API Server Configuration

When using the API server directly, you can configure it during initialization:

```python
from evrmore_accounts.api import AccountsServer

# Create server with custom configuration
server = AccountsServer(debug=True)

# Run the server on a custom port
server.run(host="127.0.0.1", port=8000)
```

## JavaScript Client Configuration

The JavaScript client can be configured during initialization:

```javascript
// Initialize with custom configuration
EvrmoreAccounts.init({
  apiUrl: 'https://your-api-server.com/api',
  autoRefresh: true,
  debug: true
});
```

### JavaScript Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `apiUrl` | URL of the API server | `/api` |
| `autoRefresh` | Automatically refresh tokens before expiration | `true` |
| `debug` | Enable debug logging | `false` |

## CORS Configuration

By default, Evrmore Accounts allows cross-origin requests from any origin. You can configure CORS settings by modifying the `evrmore_accounts/api/server.py` file:

```python
# Initialize Flask app
self.app = Flask(__name__)
CORS(self.app, resources={r"/api/*": {"origins": "https://yourdomain.com"}})
```

## Customizing Templates

You can customize the HTML templates by copying the files from `evrmore_accounts/templates` to your project and modifying them. Then, configure Flask to use your custom templates:

```python
from flask import Flask

app = Flask(__name__, template_folder="your_custom_templates")
```

## Next Steps

- Learn about the [authentication flow](authentication-flow.md)
- Explore [example integrations](../examples/basic.md)
- Check out the [API reference](../api/backend.md) 