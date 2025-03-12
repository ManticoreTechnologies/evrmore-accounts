# Basic Integration Example

This example shows how to integrate Evrmore Accounts into a basic web application.

## HTML Structure

Start with a simple HTML structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Evrmore Accounts Example</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            padding: 30px;
            width: 100%;
            max-width: 500px;
            margin: 20px 0;
        }
        .hidden {
            display: none;
        }
        .btn {
            background-color: #6434eb;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Evrmore Accounts Example</h1>
        
        <!-- Authentication Card -->
        <div class="card">
            <!-- Login State -->
            <div id="login-container">
                <h2>Sign in with Evrmore</h2>
                <p>Authenticate securely using your Evrmore wallet</p>
                
                <button id="sign-in-button" class="btn">Sign in with Evrmore</button>
            </div>
            
            <!-- Authenticated State -->
            <div id="user-container" class="hidden">
                <h2>Welcome!</h2>
                <p>You are signed in as:</p>
                <div id="user-info">
                    <p><strong>Address:</strong> <span id="user-address"></span></p>
                </div>
                
                <button id="sign-out-button" class="btn">Sign Out</button>
            </div>
        </div>
        
        <!-- Protected Content -->
        <div class="card hidden" id="protected-content">
            <h2>Protected Content</h2>
            <p>This content is only visible to authenticated users.</p>
        </div>
    </div>
    
    <!-- Include the Evrmore Accounts JavaScript -->
    <script src="https://cdn.manticore.technology/evrmore-accounts.js"></script>
    <script>
        // Your JavaScript will go here
    </script>
</body>
</html>
```

## Adding the JavaScript

Now, add the JavaScript code to handle authentication:

```javascript
// Initialize when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Evrmore Accounts
    EvrmoreAccounts.init({
        apiUrl: '/api',
        debug: true
    });
    
    // Get UI elements
    const loginContainer = document.getElementById('login-container');
    const userContainer = document.getElementById('user-container');
    const userAddress = document.getElementById('user-address');
    const protectedContent = document.getElementById('protected-content');
    const signOutButton = document.getElementById('sign-out-button');
    
    // Initialize sign-in button
    EvrmoreAccounts.initSignInButton('#sign-in-button');
    
    // Listen for authentication state changes
    EvrmoreAccounts.onAuthStateChanged(function(user) {
        if (user) {
            console.log('User is signed in:', user);
            
            // Update UI for authenticated state
            loginContainer.classList.add('hidden');
            userContainer.classList.remove('hidden');
            protectedContent.classList.remove('hidden');
            
            // Display user info
            userAddress.textContent = user.evrmore_address;
        } else {
            console.log('User is signed out');
            
            // Update UI for unauthenticated state
            loginContainer.classList.remove('hidden');
            userContainer.classList.add('hidden');
            protectedContent.classList.add('hidden');
        }
    });
    
    // Sign out button handler
    signOutButton.addEventListener('click', function() {
        EvrmoreAccounts.signOut();
    });
});
```

## Complete Example

Here's the complete example:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Evrmore Accounts Example</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            padding: 30px;
            width: 100%;
            max-width: 500px;
            margin: 20px 0;
        }
        .hidden {
            display: none;
        }
        .btn {
            background-color: #6434eb;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Evrmore Accounts Example</h1>
        
        <!-- Authentication Card -->
        <div class="card">
            <!-- Login State -->
            <div id="login-container">
                <h2>Sign in with Evrmore</h2>
                <p>Authenticate securely using your Evrmore wallet</p>
                
                <button id="sign-in-button" class="btn">Sign in with Evrmore</button>
            </div>
            
            <!-- Authenticated State -->
            <div id="user-container" class="hidden">
                <h2>Welcome!</h2>
                <p>You are signed in as:</p>
                <div id="user-info">
                    <p><strong>Address:</strong> <span id="user-address"></span></p>
                </div>
                
                <button id="sign-out-button" class="btn">Sign Out</button>
            </div>
        </div>
        
        <!-- Protected Content -->
        <div class="card hidden" id="protected-content">
            <h2>Protected Content</h2>
            <p>This content is only visible to authenticated users.</p>
        </div>
    </div>
    
    <!-- Include the Evrmore Accounts JavaScript -->
    <script src="https://cdn.manticore.technology/evrmore-accounts.js"></script>
    <script>
        // Initialize when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize Evrmore Accounts
            EvrmoreAccounts.init({
                apiUrl: '/api',
                debug: true
            });
            
            // Get UI elements
            const loginContainer = document.getElementById('login-container');
            const userContainer = document.getElementById('user-container');
            const userAddress = document.getElementById('user-address');
            const protectedContent = document.getElementById('protected-content');
            const signOutButton = document.getElementById('sign-out-button');
            
            // Initialize sign-in button
            EvrmoreAccounts.initSignInButton('#sign-in-button');
            
            // Listen for authentication state changes
            EvrmoreAccounts.onAuthStateChanged(function(user) {
                if (user) {
                    console.log('User is signed in:', user);
                    
                    // Update UI for authenticated state
                    loginContainer.classList.add('hidden');
                    userContainer.classList.remove('hidden');
                    protectedContent.classList.remove('hidden');
                    
                    // Display user info
                    userAddress.textContent = user.evrmore_address;
                } else {
                    console.log('User is signed out');
                    
                    // Update UI for unauthenticated state
                    loginContainer.classList.remove('hidden');
                    userContainer.classList.add('hidden');
                    protectedContent.classList.add('hidden');
                }
            });
            
            // Sign out button handler
            signOutButton.addEventListener('click', function() {
                EvrmoreAccounts.signOut();
            });
        });
    </script>
</body>
</html>
```

## Running the Example

1. Save the above code to a file named `index.html`
2. Make sure the Evrmore Accounts server is running
3. Open the HTML file in a web browser
4. Click the "Sign in with Evrmore" button to start the authentication flow

## Next Steps

- Customize the UI to match your application's design
- Add error handling for authentication failures
- Implement a custom challenge handler for a better user experience
- Explore the [JavaScript API Reference](../api/javascript.md) for more advanced options 