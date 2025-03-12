# Customization Guide

This guide explains how to customize the Evrmore Accounts package to match your application's requirements and branding.

## Customizing the UI

### Styling

The Evrmore Accounts package comes with default styling that you can customize to match your application's design.

#### CSS Customization

1. **Create a custom CSS file** in your application:

   ```css
   /* custom-evrmore-accounts.css */
   .evrmore-accounts-container {
     background-color: #f5f5f5;
     border-radius: 8px;
     box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
     padding: 20px;
     max-width: 400px;
     margin: 0 auto;
   }
   
   .evrmore-accounts-button {
     background-color: #4a90e2;
     color: white;
     border: none;
     padding: 10px 15px;
     border-radius: 4px;
     cursor: pointer;
     font-weight: bold;
   }
   
   .evrmore-accounts-button:hover {
     background-color: #357ab8;
   }
   
   /* Add more custom styles as needed */
   ```

2. **Include your custom CSS** after the Evrmore Accounts JavaScript:

   ```html
   <script src="/evrmore_accounts/static/evrmore-accounts.js"></script>
   <link rel="stylesheet" href="/path/to/custom-evrmore-accounts.css">
   ```

#### Customizing the Logo

You can replace the default Evrmore logo with your own:

```javascript
const evrmoreAccounts = new EvrmoreAccounts({
  apiUrl: 'http://localhost:5000/api',
  logo: '/path/to/your-logo.svg',
  logoAlt: 'Your Company Name'
});
```

### HTML Templates

For more extensive customization, you can override the default HTML templates:

1. **Create custom templates** in your application:

   ```javascript
   const customTemplates = {
     loginButton: `
       <button class="custom-login-button" id="evrmore-login-button">
         <img src="/path/to/wallet-icon.svg" alt="Wallet">
         Sign in with Blockchain
       </button>
     `,
     challengePrompt: `
       <div class="custom-challenge-container">
         <h3>Verify Your Identity</h3>
         <p>Please sign this message with your Evrmore wallet:</p>
         <div class="challenge-text">{{challenge}}</div>
         <div class="instructions">
           <p>1. Copy the text above</p>
           <p>2. Sign it with your wallet</p>
           <p>3. Paste the signature below</p>
         </div>
         <textarea id="evrmore-signature-input" placeholder="Paste your signature here"></textarea>
         <button id="evrmore-submit-signature">Verify Signature</button>
         <button id="evrmore-cancel-auth">Cancel</button>
       </div>
     `,
     userProfile: `
       <div class="custom-profile-container">
         <h3>Welcome, Blockchain User!</h3>
         <p>Address: {{address}}</p>
         <p>User since: {{created_at}}</p>
         <button id="evrmore-logout-button">Sign Out</button>
       </div>
     `
   };
   
   const evrmoreAccounts = new EvrmoreAccounts({
     apiUrl: 'http://localhost:5000/api',
     templates: customTemplates
   });
   ```

2. **Available template placeholders**:
   - `{{challenge}}` - The challenge text to be signed
   - `{{address}}` - The user's Evrmore address
   - `{{created_at}}` - The user's account creation date
   - `{{last_login}}` - The user's last login date

## Customizing the Backend

### Environment Variables

Customize the behavior of the Evrmore Accounts backend by setting these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for JWT token signing | Random string |
| `JWT_EXPIRATION` | JWT token expiration time in seconds | 3600 (1 hour) |
| `REFRESH_TOKEN_EXPIRATION` | Refresh token expiration in seconds | 2592000 (30 days) |
| `CHALLENGE_EXPIRATION` | Challenge expiration time in seconds | 300 (5 minutes) |
| `DATABASE_PATH` | Path to SQLite database file | `evrmore_accounts/data/users.db` |
| `CORS_ORIGINS` | Comma-separated list of allowed origins | `*` |

Example:

```bash
export JWT_SECRET="your-secure-secret-key"
export JWT_EXPIRATION=7200
export CORS_ORIGINS="https://yourdomain.com,https://app.yourdomain.com"
python3 -m evrmore_accounts.app
```

### Custom Database

By default, Evrmore Accounts uses SQLite for storing user data. You can extend the package to use a different database:

1. **Create a custom database adapter**:

   ```python
   # custom_db_adapter.py
   from evrmore_accounts.db import DatabaseAdapter
   import pymysql
   
   class MySQLAdapter(DatabaseAdapter):
       def __init__(self, host, user, password, database):
           self.connection = pymysql.connect(
               host=host,
               user=user,
               password=password,
               database=database
           )
       
       def get_user(self, address):
           cursor = self.connection.cursor()
           cursor.execute("SELECT * FROM users WHERE address = %s", (address,))
           user = cursor.fetchone()
           cursor.close()
           if not user:
               return None
           return {
               "address": user[0],
               "created_at": user[1],
               "last_login": user[2]
           }
       
       # Implement other required methods...
   ```

2. **Use your custom adapter**:

   ```python
   # custom_app.py
   from evrmore_accounts.app import create_app
   from custom_db_adapter import MySQLAdapter
   
   db_adapter = MySQLAdapter(
       host="localhost",
       user="dbuser",
       password="dbpassword",
       database="evrmore_accounts"
   )
   
   app = create_app(db_adapter=db_adapter)
   
   if __name__ == "__main__":
       app.run(host="0.0.0.0", port=5000)
   ```

### Custom Authentication Logic

You can extend the authentication process with custom logic:

1. **Create a custom authentication handler**:

   ```python
   # custom_auth.py
   from evrmore_accounts.auth import AuthHandler
   
   class CustomAuthHandler(AuthHandler):
       def __init__(self, db_adapter):
           super().__init__(db_adapter)
       
       def authenticate(self, address, signature, challenge):
           # First perform standard authentication
           result = super().authenticate(address, signature, challenge)
           
           if result.get("success"):
               # Add custom logic after successful authentication
               # For example, check if user is in an allowlist
               if not self._is_in_allowlist(address):
                   return {"success": False, "error": "Address not in allowlist"}
           
           return result
       
       def _is_in_allowlist(self, address):
           # Custom logic to check if address is allowed
           allowed_addresses = ["EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc", "EQzZZEjNNUcmBfYCgaQSSoV2K3jxJcHYQ3"]
           return address in allowed_addresses
   ```

2. **Use your custom handler**:

   ```python
   # custom_app.py
   from evrmore_accounts.app import create_app
   from evrmore_accounts.db import SQLiteAdapter
   from custom_auth import CustomAuthHandler
   
   db_adapter = SQLiteAdapter("evrmore_accounts/data/users.db")
   auth_handler = CustomAuthHandler(db_adapter)
   
   app = create_app(db_adapter=db_adapter, auth_handler=auth_handler)
   
   if __name__ == "__main__":
       app.run(host="0.0.0.0", port=5000)
   ```

## Extending the API

You can extend the API with custom endpoints:

```python
# custom_app.py
from evrmore_accounts.app import create_app
from flask import jsonify, request

app = create_app()

# Add custom endpoints
@app.route("/api/custom/user-stats", methods=["GET"])
def user_stats():
    # Get the authenticated user from the request
    user = request.user  # Set by the JWT middleware
    
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    # Custom logic to get user stats
    stats = {
        "address": user["address"],
        "login_count": 42,  # Example data
        "last_activity": "2025-03-12T10:30:00Z"
    }
    
    return jsonify(stats)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

## JavaScript Client Customization

### Custom Event Handlers

You can add custom event handlers to the JavaScript client:

```javascript
const evrmoreAccounts = new EvrmoreAccounts({
  apiUrl: 'http://localhost:5000/api'
});

// Standard events
evrmoreAccounts.on('authenticated', (user) => {
  console.log('User authenticated:', user);
  // Custom logic after authentication
  trackUserLogin(user.address);
});

evrmoreAccounts.on('error', (error) => {
  console.error('Authentication error:', error);
  // Custom error handling
  showCustomErrorNotification(error.message);
});

// Custom helper functions
function trackUserLogin(address) {
  // Analytics tracking
  analytics.track('user_login', { address });
}

function showCustomErrorNotification(message) {
  // Custom UI notification
  const notification = document.createElement('div');
  notification.className = 'error-notification';
  notification.textContent = message;
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.remove();
  }, 5000);
}
```

### Extending the JavaScript Client

You can extend the JavaScript client with custom functionality:

```javascript
// Extend the EvrmoreAccounts class
class CustomEvrmoreAccounts extends EvrmoreAccounts {
  constructor(options) {
    super(options);
    this.customOptions = options.customOptions || {};
  }
  
  // Add custom methods
  async getUserStats() {
    if (!this.isAuthenticated()) {
      throw new Error('User not authenticated');
    }
    
    const response = await fetch(`${this.apiUrl}/custom/user-stats`, {
      headers: {
        'Authorization': `Bearer ${this.getToken()}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch user stats');
    }
    
    return await response.json();
  }
}

// Use the extended class
const evrmoreAccounts = new CustomEvrmoreAccounts({
  apiUrl: 'http://localhost:5000/api',
  customOptions: {
    theme: 'dark',
    analyticsEnabled: true
  }
});

// Use custom methods
async function displayUserStats() {
  try {
    const stats = await evrmoreAccounts.getUserStats();
    console.log('User stats:', stats);
    // Update UI with stats
  } catch (error) {
    console.error('Error fetching user stats:', error);
  }
}
```

## Complete Example

Here's a complete example combining several customization techniques:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Custom Evrmore Accounts Integration</title>
  
  <!-- Base styles -->
  <link rel="stylesheet" href="/evrmore_accounts/static/evrmore-accounts.css">
  
  <!-- Custom styles -->
  <link rel="stylesheet" href="/path/to/custom-evrmore-accounts.css">
  
  <style>
    /* Additional page styling */
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    
    .app-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 40px;
      border-bottom: 1px solid #eee;
      padding-bottom: 20px;
    }
    
    .app-content {
      display: flex;
      flex-direction: column;
      align-items: center;
    }
  </style>
</head>
<body>
  <div class="app-header">
    <h1>My Custom Application</h1>
    <div id="auth-container"></div>
  </div>
  
  <div class="app-content">
    <div id="protected-content" style="display: none;">
      <h2>Protected Content</h2>
      <p>This content is only visible to authenticated users.</p>
      <button id="load-stats">Load User Stats</button>
      <div id="user-stats"></div>
    </div>
    
    <div id="public-content">
      <h2>Public Content</h2>
      <p>This content is visible to everyone.</p>
    </div>
  </div>
  
  <!-- Evrmore Accounts JavaScript -->
  <script src="/evrmore_accounts/static/evrmore-accounts.js"></script>
  
  <!-- Custom integration script -->
  <script>
    // Extend the EvrmoreAccounts class
    class CustomEvrmoreAccounts extends EvrmoreAccounts {
      constructor(options) {
        super(options);
      }
      
      async getUserStats() {
        if (!this.isAuthenticated()) {
          throw new Error('User not authenticated');
        }
        
        const response = await fetch(`${this.apiUrl}/custom/user-stats`, {
          headers: {
            'Authorization': `Bearer ${this.getToken()}`
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch user stats');
        }
        
        return await response.json();
      }
    }
    
    // Custom templates
    const customTemplates = {
      loginButton: `
        <button class="custom-login-button" id="evrmore-login-button">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M19 7h-3V5a3 3 0 0 0-3-3h-2a3 3 0 0 0-3 3v2H5a3 3 0 0 0-3 3v8a3 3 0 0 0 3 3h14a3 3 0 0 0 3-3v-8a3 3 0 0 0-3-3zm-9-2a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v2h-4V5zm10 13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v8z" fill="currentColor"/>
            <path d="M12 14a1 1 0 0 0-1 1v2a1 1 0 0 0 2 0v-2a1 1 0 0 0-1-1z" fill="currentColor"/>
          </svg>
          Sign in with Blockchain
        </button>
      `,
      userProfile: `
        <div class="custom-profile-container">
          <div class="user-info">
            <span class="user-address">{{address}}</span>
            <span class="user-since">Member since: {{created_at}}</span>
          </div>
          <button id="evrmore-logout-button" class="logout-button">Sign Out</button>
        </div>
      `
    };
    
    // Initialize the custom client
    const evrmoreAccounts = new CustomEvrmoreAccounts({
      apiUrl: 'http://localhost:5000/api',
      containerId: 'auth-container',
      templates: customTemplates,
      logo: '/path/to/custom-logo.svg',
      logoAlt: 'My Company'
    });
    
    // Event handlers
    evrmoreAccounts.on('authenticated', (user) => {
      console.log('User authenticated:', user);
      document.getElementById('protected-content').style.display = 'block';
      document.getElementById('public-content').style.display = 'none';
      
      // Analytics tracking (example)
      if (window.analytics) {
        window.analytics.identify(user.address);
        window.analytics.track('User Login');
      }
    });
    
    evrmoreAccounts.on('logout', () => {
      console.log('User logged out');
      document.getElementById('protected-content').style.display = 'none';
      document.getElementById('public-content').style.display = 'block';
      document.getElementById('user-stats').innerHTML = '';
      
      // Analytics tracking (example)
      if (window.analytics) {
        window.analytics.track('User Logout');
      }
    });
    
    evrmoreAccounts.on('error', (error) => {
      console.error('Authentication error:', error);
      // Show custom error notification
      alert(`Authentication error: ${error.message}`);
    });
    
    // Check authentication status on page load
    document.addEventListener('DOMContentLoaded', () => {
      if (evrmoreAccounts.isAuthenticated()) {
        document.getElementById('protected-content').style.display = 'block';
        document.getElementById('public-content').style.display = 'none';
      } else {
        document.getElementById('protected-content').style.display = 'none';
        document.getElementById('public-content').style.display = 'block';
      }
      
      // Load user stats button
      document.getElementById('load-stats').addEventListener('click', async () => {
        try {
          const stats = await evrmoreAccounts.getUserStats();
          const statsContainer = document.getElementById('user-stats');
          statsContainer.innerHTML = `
            <h3>User Stats</h3>
            <p>Address: ${stats.address}</p>
            <p>Login count: ${stats.login_count}</p>
            <p>Last activity: ${new Date(stats.last_activity).toLocaleString()}</p>
          `;
        } catch (error) {
          console.error('Error loading user stats:', error);
          document.getElementById('user-stats').innerHTML = `
            <p class="error">Error loading stats: ${error.message}</p>
          `;
        }
      });
    });
  </script>
</body>
</html>
```

## Next Steps

After customizing Evrmore Accounts for your application:

1. Test thoroughly to ensure all customizations work as expected
2. Consider contributing useful customizations back to the main project
3. Check the [Security Guide](../development/security.md) for best practices
4. Review the [API Reference](../reference/api.md) for additional customization options 