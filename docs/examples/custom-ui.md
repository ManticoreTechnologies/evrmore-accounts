# Custom UI Example

This example shows how to create a custom UI for Evrmore Accounts authentication.

## Overview

While Evrmore Accounts provides a simple sign-in button that handles the authentication flow, you might want to create a custom UI for a more tailored user experience. This example demonstrates how to implement a custom authentication UI using the Evrmore Accounts JavaScript library.

## Custom Challenge Handler

The key to creating a custom UI is implementing a custom challenge handler. This function is called when a challenge is generated and allows you to control how the challenge is presented to the user and how the signature is collected.

## Example Implementation

Here's a complete example of a custom authentication UI:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custom Evrmore Authentication UI</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        
        .auth-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            padding: 30px;
            width: 100%;
            max-width: 500px;
            margin: 20px auto;
        }
        
        .auth-header {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .auth-logo {
            width: 80px;
            height: 80px;
            margin-bottom: 15px;
        }
        
        .auth-step {
            margin-bottom: 20px;
            display: none;
        }
        
        .auth-step.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .form-input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        
        .form-button {
            background-color: #6434eb;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            width: 100%;
        }
        
        .form-button:hover {
            background-color: #5729d2;
        }
        
        .challenge-box {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
            margin-bottom: 15px;
        }
        
        .status-message {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 15px;
            text-align: center;
        }
        
        .status-message.error {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .status-message.success {
            background-color: #d4edda;
            color: #155724;
        }
        
        .status-message.info {
            background-color: #cce5ff;
            color: #004085;
        }
        
        .user-profile {
            text-align: center;
        }
        
        .user-avatar {
            width: 80px;
            height: 80px;
            background-color: #6434eb;
            border-radius: 50%;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            margin: 0 auto 15px;
        }
        
        .user-address {
            font-family: monospace;
            word-break: break-all;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-header">
            <img src="/static/evrmore-logo.svg" alt="Evrmore" class="auth-logo">
            <h1>Evrmore Authentication</h1>
        </div>
        
        <!-- Step 1: Enter Evrmore Address -->
        <div id="step-address" class="auth-step active">
            <h2>Step 1: Enter Your Evrmore Address</h2>
            <div class="form-group">
                <label for="evrmore-address" class="form-label">Evrmore Address</label>
                <input type="text" id="evrmore-address" class="form-input" placeholder="EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc">
            </div>
            <button id="generate-challenge-btn" class="form-button">Generate Challenge</button>
        </div>
        
        <!-- Step 2: Sign Challenge -->
        <div id="step-challenge" class="auth-step">
            <h2>Step 2: Sign the Challenge</h2>
            <p>Please sign this challenge with your Evrmore wallet:</p>
            <div id="challenge-text" class="challenge-box"></div>
            
            <div class="form-group">
                <label for="signature" class="form-label">Signature</label>
                <input type="text" id="signature" class="form-input" placeholder="Paste your signature here">
            </div>
            <button id="verify-signature-btn" class="form-button">Verify Signature</button>
            <button id="back-to-address-btn" class="form-button" style="background-color: transparent; color: #6434eb; margin-top: 10px;">Back</button>
        </div>
        
        <!-- Step 3: Authenticated -->
        <div id="step-authenticated" class="auth-step">
            <h2>Authentication Successful</h2>
            <div class="user-profile">
                <div class="user-avatar">👤</div>
                <h3 id="user-name">User</h3>
                <div id="user-address" class="user-address"></div>
            </div>
            <button id="sign-out-btn" class="form-button">Sign Out</button>
        </div>
        
        <!-- Status Messages -->
        <div id="status-message" class="status-message" style="display: none;"></div>
    </div>
    
    <!-- Include the Evrmore Accounts JavaScript -->
    <script src="/static/evrmore-accounts.js"></script>
    <script>
        // Initialize when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize Evrmore Accounts
            EvrmoreAccounts.init({
                apiUrl: '/api',
                debug: true
            });
            
            // Get UI elements
            const stepAddress = document.getElementById('step-address');
            const stepChallenge = document.getElementById('step-challenge');
            const stepAuthenticated = document.getElementById('step-authenticated');
            const evrmoreAddressInput = document.getElementById('evrmore-address');
            const challengeText = document.getElementById('challenge-text');
            const signatureInput = document.getElementById('signature');
            const generateChallengeBtn = document.getElementById('generate-challenge-btn');
            const verifySignatureBtn = document.getElementById('verify-signature-btn');
            const backToAddressBtn = document.getElementById('back-to-address-btn');
            const signOutBtn = document.getElementById('sign-out-btn');
            const statusMessage = document.getElementById('status-message');
            const userName = document.getElementById('user-name');
            const userAddress = document.getElementById('user-address');
            
            // Store challenge data
            let currentChallenge = null;
            
            // Check if user is already authenticated
            if (EvrmoreAccounts.isAuthenticated()) {
                const user = EvrmoreAccounts.getUser();
                showAuthenticatedStep(user);
            }
            
            // Listen for authentication state changes
            EvrmoreAccounts.onAuthStateChanged(function(user) {
                if (user) {
                    showAuthenticatedStep(user);
                } else {
                    showAddressStep();
                }
            });
            
            // Generate challenge button handler
            generateChallengeBtn.addEventListener('click', function() {
                const evrmoreAddress = evrmoreAddressInput.value.trim();
                
                if (!evrmoreAddress) {
                    showStatus('Please enter your Evrmore address', 'error');
                    return;
                }
                
                showStatus('Generating challenge...', 'info');
                
                EvrmoreAccounts.signIn(evrmoreAddress)
                    .then(function(challenge) {
                        currentChallenge = challenge;
                        challengeText.textContent = challenge.challenge;
                        showChallengeStep();
                        hideStatus();
                    })
                    .catch(function(error) {
                        showStatus('Error generating challenge: ' + error.message, 'error');
                    });
            });
            
            // Verify signature button handler
            verifySignatureBtn.addEventListener('click', function() {
                const signature = signatureInput.value.trim();
                
                if (!signature) {
                    showStatus('Please enter your signature', 'error');
                    return;
                }
                
                if (!currentChallenge) {
                    showStatus('Challenge not found. Please try again.', 'error');
                    showAddressStep();
                    return;
                }
                
                showStatus('Verifying signature...', 'info');
                
                EvrmoreAccounts.authenticate({
                    evrmoreAddress: currentChallenge.address,
                    challenge: currentChallenge.challenge,
                    signature: signature
                })
                    .then(function(user) {
                        showStatus('Authentication successful!', 'success');
                        setTimeout(function() {
                            hideStatus();
                        }, 2000);
                    })
                    .catch(function(error) {
                        showStatus('Authentication failed: ' + error.message, 'error');
                    });
            });
            
            // Back button handler
            backToAddressBtn.addEventListener('click', function() {
                showAddressStep();
                currentChallenge = null;
            });
            
            // Sign out button handler
            signOutBtn.addEventListener('click', function() {
                EvrmoreAccounts.signOut()
                    .then(function() {
                        showStatus('Signed out successfully', 'success');
                        setTimeout(function() {
                            hideStatus();
                        }, 2000);
                    });
            });
            
            // Helper functions
            function showAddressStep() {
                stepAddress.classList.add('active');
                stepChallenge.classList.remove('active');
                stepAuthenticated.classList.remove('active');
                evrmoreAddressInput.value = '';
            }
            
            function showChallengeStep() {
                stepAddress.classList.remove('active');
                stepChallenge.classList.add('active');
                stepAuthenticated.classList.remove('active');
                signatureInput.value = '';
            }
            
            function showAuthenticatedStep(user) {
                stepAddress.classList.remove('active');
                stepChallenge.classList.remove('active');
                stepAuthenticated.classList.add('active');
                
                // Update user info
                userName.textContent = user.username || 'User';
                userAddress.textContent = user.evrmore_address;
            }
            
            function showStatus(message, type) {
                statusMessage.textContent = message;
                statusMessage.className = 'status-message ' + type;
                statusMessage.style.display = 'block';
            }
            
            function hideStatus() {
                statusMessage.style.display = 'none';
            }
        });
    </script>
</body>
</html>
```

## How It Works

This example implements a multi-step authentication flow:

1. **Step 1: Enter Evrmore Address**
   - The user enters their Evrmore address
   - The application generates a challenge when the user clicks the button

2. **Step 2: Sign Challenge**
   - The challenge is displayed to the user
   - The user signs the challenge with their wallet and pastes the signature
   - The application verifies the signature

3. **Step 3: Authenticated**
   - Upon successful authentication, the user's profile is displayed
   - The user can sign out

## Key Components

### Challenge Generation

```javascript
EvrmoreAccounts.signIn(evrmoreAddress)
    .then(function(challenge) {
        currentChallenge = challenge;
        challengeText.textContent = challenge.challenge;
        showChallengeStep();
    })
    .catch(function(error) {
        showStatus('Error generating challenge: ' + error.message, 'error');
    });
```

### Authentication

```javascript
EvrmoreAccounts.authenticate({
    evrmoreAddress: currentChallenge.address,
    challenge: currentChallenge.challenge,
    signature: signature
})
    .then(function(user) {
        showStatus('Authentication successful!', 'success');
    })
    .catch(function(error) {
        showStatus('Authentication failed: ' + error.message, 'error');
    });
```

### Authentication State Management

```javascript
// Check if user is already authenticated
if (EvrmoreAccounts.isAuthenticated()) {
    const user = EvrmoreAccounts.getUser();
    showAuthenticatedStep(user);
}

// Listen for authentication state changes
EvrmoreAccounts.onAuthStateChanged(function(user) {
    if (user) {
        showAuthenticatedStep(user);
    } else {
        showAddressStep();
    }
});
```

## Customization Options

You can customize this example in several ways:

1. **UI Design**: Modify the CSS to match your application's design
2. **Flow Steps**: Add or remove steps in the authentication flow
3. **Error Handling**: Implement more detailed error handling
4. **User Profile**: Display additional user information
5. **Integration**: Integrate with your application's navigation and state management

## Next Steps

- Explore the [JavaScript API Reference](../api/javascript.md) for more advanced options
- Learn about the [authentication flow](../guide/authentication-flow.md)
- Check out the [backend API](../api/backend.md) for server-side integration 