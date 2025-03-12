# Quick Start Guide

This guide will help you get up and running with Evrmore Accounts quickly.

## Running the Server

After [installing](installation.md) Evrmore Accounts, you can start the server with:

```bash
python3 -m evrmore_accounts.app
```

This will start a Flask server on `http://localhost:5000` with both the API endpoints and a web interface.

## Exploring the Demo

Open `http://localhost:5000/demo` in your web browser to see the authentication flow in action. The demo provides a complete example of:

1. Generating a challenge for a user's Evrmore address
2. Signing the challenge with an Evrmore wallet
3. Authenticating with the signed challenge
4. Accessing authenticated resources

## Integration Example

Check out the simple integration example at `http://localhost:5000/example`. This shows how to integrate Evrmore Accounts with your web application using the JavaScript client library.

## API Endpoints

The following API endpoints are available:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/challenge` | POST | Generate a challenge for a user |
| `/api/authenticate` | POST | Authenticate with a signed challenge |
| `/api/validate` | GET | Validate a JWT token |
| `/api/user` | GET | Get authenticated user information |
| `/api/logout` | POST | Invalidate a JWT token (logout) |

## JavaScript Client Library

To use Evrmore Accounts in your web application, add the JavaScript client library:

```html
<script src="http://your-server.com/static/evrmore-accounts.js"></script>
```

Initialize the library and create a sign-in button:

```javascript
// Initialize Evrmore Accounts
EvrmoreAccounts.init({
  apiUrl: 'http://your-server.com/api',
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

## What's Next?

- Learn more about the [authentication flow](authentication-flow.md)
- Explore the [API reference](../api/backend.md)
- Check out the [JavaScript library documentation](../api/javascript.md)
- See [example integrations](../examples/basic.md) 