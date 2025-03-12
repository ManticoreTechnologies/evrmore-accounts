# JavaScript Client API Reference

The Evrmore Accounts JavaScript client library provides client-side functionality for authentication with the Evrmore Accounts backend.

## Installation

### Loading from CDN

```html
<script src="https://cdn.manticore.technology/static/evrmore-accounts.js"></script>
```

### Loading from your server

```html
<script src="http://your-server.com/static/evrmore-accounts.js"></script>
```

## Initialization

Initialize the library with configuration options:

```javascript
EvrmoreAccounts.init({
  apiUrl: 'https://auth.manticore.technology/api',  // API endpoint URL
  autoRefresh: true,                               // Auto-refresh authentication (default: true)
  debug: false                                     // Enable debug logging (default: false)
});
```

## Core Methods

### Checking Authentication Status

Check if the user is authenticated:

```javascript
const isAuthenticated = EvrmoreAccounts.isAuthenticated();
console.log('User is authenticated:', isAuthenticated);
```

### Getting User Information

Get information about the authenticated user:

```javascript
const user = EvrmoreAccounts.getUser();
if (user) {
  console.log('User ID:', user.id);
  console.log('Evrmore Address:', user.evrmore_address);
}
```

### Getting Authentication Token

Get the current authentication token:

```javascript
const token = EvrmoreAccounts.getToken();
console.log('Authentication token:', token);
```

### Sign In

Start the sign-in flow by generating a challenge for a user:

```javascript
EvrmoreAccounts.signIn('EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc')
  .then(function(challenge) {
    console.log('Challenge generated:', challenge.challenge);
    console.log('Expires at:', challenge.expires_at);
    
    // The user would sign this challenge with their wallet
    // and then you would call the authenticate method
  })
  .catch(function(error) {
    console.error('Error generating challenge:', error);
  });
```

### Authenticate

Authenticate with a signed challenge:

```javascript
EvrmoreAccounts.authenticate({
  evrmoreAddress: 'EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc',
  challenge: 'Sign this message to authenticate with Evrmore: EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc:1741815113:c4365fe48492d73f',
  signature: 'H9zHnUbwvQiXpAHnYDxkTRxCHRUKzQXQ3QNAyA+9SJKmEtFfMn7Z5JJXRQs29Jzf6HjA0e2yqC1Xk/9M94Uz6Sc='
})
  .then(function(user) {
    console.log('User authenticated:', user);
  })
  .catch(function(error) {
    console.error('Authentication error:', error);
  });
```

### Sign Out

Sign the user out:

```javascript
EvrmoreAccounts.signOut()
  .then(function() {
    console.log('User signed out');
  })
  .catch(function(error) {
    console.error('Sign out error:', error);
  });
```

## Event Listeners

### Authentication State Changes

Listen for authentication state changes:

```javascript
const unsubscribe = EvrmoreAccounts.onAuthStateChanged(function(user) {
  if (user) {
    console.log('User is signed in:', user);
    // Show authenticated UI
  } else {
    console.log('User is signed out');
    // Show sign-in UI
  }
});

// Later, to stop listening
unsubscribe();
```

## UI Components

### Sign-In Button

Initialize a sign-in button:

```javascript
EvrmoreAccounts.initSignInButton('#sign-in-button');
```

With custom options:

```javascript
EvrmoreAccounts.initSignInButton('#sign-in-button', {
  evrmoreAddress: 'EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc',  // Pre-fill address
  onChallenge: function(challenge, completeAuth) {
    // Custom challenge handling logic
    console.log('Challenge:', challenge.challenge);
    
    // When the user has signed the challenge
    const signature = '...'; // Get signature from user
    completeAuth(signature);
  }
});
```

## Storage and Security

The library automatically:

1. Stores authentication tokens in localStorage
2. Validates tokens on page load
3. Refreshes tokens automatically if `autoRefresh` is enabled
4. Clears tokens on sign out or when they become invalid

## Browser Compatibility

The library is compatible with:

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- IE11 (with polyfills)

## Error Handling

All asynchronous methods return promises that can be caught for error handling:

```javascript
EvrmoreAccounts.signIn('EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc')
  .then(function(challenge) {
    // Success
  })
  .catch(function(error) {
    // Handle error
    console.error('Error:', error.message);
  });
``` 