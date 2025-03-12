/**
 * Evrmore Accounts
 * Client-side library for authentication with Evrmore blockchain wallets
 * By Manticore Technologies - https://manticore.technology
 */

(function(window) {
  'use strict';

  // Private variables
  let _config = {
    apiUrl: 'https://auth.manticore.technology/api',
    debug: false,
    autoRefresh: true
  };

  let _token = null;
  let _tokenExpires = null;
  let _user = null;
  let _authStateListeners = {};
  let _autoRefreshTimer = null;

  /**
   * Log messages to console if debug mode is enabled
   */
  function _log(...args) {
    if (_config.debug) {
      console.log('[EvrmoreAccounts]', ...args);
    }
  }

  /**
   * Generate a random ID for listener subscription
   */
  function _generateId() {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }

  /**
   * Ensure URL is absolute and points to auth.manticore.technology
   */
  function _getFullApiUrl(endpoint) {
    // Always use the auth.manticore.technology domain for API calls
    const baseUrl = 'https://auth.manticore.technology/api';
    
    // Clean up the endpoint to ensure no double slashes
    const cleanEndpoint = endpoint.replace(/^\//, '');
    
    // Combine with a proper separator
    const url = baseUrl + (baseUrl.endsWith('/') ? '' : '/') + cleanEndpoint;
    
    _log('API URL constructed:', url);
    return url;
  }

  /**
   * Make an API call to the server
   */
  async function _apiCall(endpoint, method, data, includeToken = false) {
    const url = _getFullApiUrl(endpoint);
    _log(`Making ${method} request to: ${url}`);

    const headers = {
      'Content-Type': 'application/json'
    };

    if (includeToken && _token) {
      headers['Authorization'] = `Bearer ${_token}`;
      _log('Including authentication token in request');
    }

    try {
      const response = await fetch(url, {
        method: method,
        headers: headers,
        body: data ? JSON.stringify(data) : undefined
      });

      if (response.ok) {
        const responseData = await response.json();
        _log('API response:', responseData);
        return responseData;
      } else {
        let errorData = null;
        try {
          errorData = await response.json();
        } catch (e) {
          // If response is not JSON
          errorData = { message: response.statusText };
        }
        
        const error = new Error(errorData.message || 'API request failed');
        error.status = response.status;
        error.data = errorData;
        throw error;
      }
    } catch (error) {
      _log('API call error:', error);
      throw error;
    }
  }

  /**
   * Generate a challenge for the user to sign
   */
  async function _generateChallenge(evrmoreAddress) {
    _log('Generating challenge for address:', evrmoreAddress);
    return await _apiCall('challenge', 'POST', { evrmore_address: evrmoreAddress });
  }

  /**
   * Authenticate with a signed challenge
   */
  async function _authenticate(authData) {
    _log('Authenticating with signed challenge');
    const result = await _apiCall('authenticate', 'POST', {
      evrmore_address: authData.evrmoreAddress,
      challenge: authData.challenge,
      signature: authData.signature
    });

    if (result.token) {
      _setAuthentication(result.token, result.expires_at, result.user);
      return result.user;
    } else {
      throw new Error('Authentication failed: No token received');
    }
  }

  /**
   * Validate the current token
   */
  async function _validateToken(token) {
    _log('Validating token');
    return await _apiCall('validate', 'GET', null, true);
  }

  /**
   * Get current user information
   */
  async function _getUserInfo() {
    _log('Getting user information');
    return await _apiCall('user', 'GET', null, true);
  }

  /**
   * Invalidate the current token (logout)
   */
  async function _invalidateToken() {
    _log('Invalidating token (logging out)');
    if (_token) {
      try {
        await _apiCall('logout', 'POST', null, true);
      } catch (error) {
        _log('Error during logout:', error);
        // Continue with logout process even if API call fails
      }
      _clearAuthentication();
      return true;
    }
    return false;
  }

  /**
   * Set authentication state
   */
  function _setAuthentication(token, tokenExpires, user) {
    _log('Setting authentication state');
    _token = token;
    _tokenExpires = new Date(tokenExpires);
    _user = user;

    // Store in localStorage
    localStorage.setItem('evrmore_accounts_token', token);
    localStorage.setItem('evrmore_accounts_token_expires', tokenExpires);
    localStorage.setItem('evrmore_accounts_user', JSON.stringify(user));

    // Setup auto refresh if enabled
    if (_config.autoRefresh) {
      _setupAutoRefresh();
    }

    // Notify listeners
    _notifyListeners();
  }

  /**
   * Clear authentication state
   */
  function _clearAuthentication() {
    _log('Clearing authentication state');
    _token = null;
    _tokenExpires = null;
    _user = null;

    // Clear from localStorage
    localStorage.removeItem('evrmore_accounts_token');
    localStorage.removeItem('evrmore_accounts_token_expires');
    localStorage.removeItem('evrmore_accounts_user');

    // Clear auto refresh timer
    if (_autoRefreshTimer) {
      clearTimeout(_autoRefreshTimer);
      _autoRefreshTimer = null;
    }

    // Notify listeners
    _notifyListeners();
  }

  /**
   * Load authentication from storage
   */
  function _loadFromStorage() {
    _log('Loading authentication from storage');
    const token = localStorage.getItem('evrmore_accounts_token');
    const tokenExpires = localStorage.getItem('evrmore_accounts_token_expires');
    const user = localStorage.getItem('evrmore_accounts_user');

    if (token && tokenExpires && user) {
      const expiresDate = new Date(tokenExpires);
      
      // Check if token is still valid
      if (expiresDate > new Date()) {
        _log('Valid token found in storage, expires:', expiresDate);
        _token = token;
        _tokenExpires = expiresDate;
        
        try {
          _user = JSON.parse(user);
        } catch (e) {
          _log('Error parsing user data:', e);
          _user = null;
        }

        // Setup auto refresh if enabled
        if (_config.autoRefresh) {
          _setupAutoRefresh();
        }

        // Validate the token with the server
        _validateToken(token)
          .then(result => {
            if (!result.valid) {
              _log('Token validation failed, clearing authentication');
              _clearAuthentication();
            } else {
              _log('Token validated successfully');
            }
          })
          .catch(error => {
            _log('Error validating token:', error);
            _clearAuthentication();
          });

        return true;
      } else {
        _log('Expired token found in storage, clearing');
        localStorage.removeItem('evrmore_accounts_token');
        localStorage.removeItem('evrmore_accounts_token_expires');
        localStorage.removeItem('evrmore_accounts_user');
      }
    } else {
      _log('No token found in storage');
    }

    return false;
  }

  /**
   * Setup token auto refresh
   */
  function _setupAutoRefresh() {
    _log('Setting up token auto refresh');
    if (_autoRefreshTimer) {
      clearTimeout(_autoRefreshTimer);
      _autoRefreshTimer = null;
    }

    if (_token && _tokenExpires) {
      const now = new Date();
      const expiresIn = _tokenExpires.getTime() - now.getTime();
      const refreshIn = expiresIn - (30 * 60 * 1000); // Refresh 30 minutes before expiration

      if (refreshIn > 0) {
        _log('Token will auto-refresh in', Math.round(refreshIn / 1000 / 60), 'minutes');
        _autoRefreshTimer = setTimeout(async () => {
          _log('Auto-refreshing token');
          try {
            const result = await _validateToken(_token);
            if (result.valid) {
              _log('Token refreshed successfully');
            } else {
              _log('Token refresh failed, clearing authentication');
              _clearAuthentication();
            }
          } catch (error) {
            _log('Error refreshing token:', error);
            _clearAuthentication();
          }
        }, refreshIn);
      } else {
        _log('Token already expired or close to expiration');
        _clearAuthentication();
      }
    }
  }

  /**
   * Notify authentication state change listeners
   */
  function _notifyListeners() {
    _log('Notifying auth state listeners');
    const user = _user;
    
    Object.keys(_authStateListeners).forEach(id => {
      try {
        _authStateListeners[id](user);
      } catch (error) {
        _log('Error in auth state listener:', error);
      }
    });
  }

  /**
   * Initialize sign-in button
   */
  function _initSignInButton(selector, options = {}) {
    _log('Initializing sign-in button:', selector);
    const button = document.querySelector(selector);
    if (!button) {
      throw new Error(`Sign-in button not found: ${selector}`);
    }

    options = options || {};
    const evrmoreAddress = options.evrmoreAddress || '';
    const onChallenge = options.onChallenge;

    button.addEventListener('click', async function(e) {
      e.preventDefault();
      _log('Sign-in button clicked');

      let address = evrmoreAddress;
      if (!address) {
        address = prompt('Enter your Evrmore address:');
        if (!address) return;
      }

      try {
        const challenge = await EvrmoreAccounts.signIn(address);
        _log('Challenge generated:', challenge);

        if (onChallenge && typeof onChallenge === 'function') {
          onChallenge(challenge, (signature) => {
            return EvrmoreAccounts.authenticate({
              evrmoreAddress: address,
              challenge: challenge.challenge,
              signature: signature
            });
          });
        } else {
          // Default challenge handling
          const signature = prompt('Sign this message with your Evrmore wallet and paste the signature here:\n\n' + challenge.challenge);
          if (signature) {
            await EvrmoreAccounts.authenticate({
              evrmoreAddress: address,
              challenge: challenge.challenge,
              signature: signature
            });
          }
        }
      } catch (error) {
        _log('Error during sign-in:', error);
        alert('Error: ' + (error.message || 'Failed to authenticate'));
      }
    });

    _log('Sign-in button initialized');
  }

  // Public API
  const EvrmoreAccounts = {
    /**
     * Initialize the library
     */
    init: function(options) {
      _log('Initializing EvrmoreAccounts');
      options = options || {};
      
      // Always force to use auth.manticore.technology for API calls
      _config = {
        apiUrl: 'https://auth.manticore.technology/api',
        debug: !!options.debug,
        autoRefresh: options.autoRefresh !== false
      };
      
      _log('Initialized with config:', _config);
      
      // Load from storage
      _loadFromStorage();
      
      return this;
    },

    /**
     * Check if user is authenticated
     */
    isAuthenticated: function() {
      return !!_token && !!_user && (_tokenExpires > new Date());
    },

    /**
     * Get the authenticated user
     */
    getUser: function() {
      return _user;
    },

    /**
     * Get the authentication token
     */
    getToken: function() {
      return _token;
    },

    /**
     * Generate a challenge for signing
     */
    signIn: async function(evrmoreAddress) {
      return await _generateChallenge(evrmoreAddress);
    },

    /**
     * Authenticate with a signed challenge
     */
    authenticate: async function(authData) {
      return await _authenticate(authData);
    },

    /**
     * Sign out the current user
     */
    signOut: async function() {
      return await _invalidateToken();
    },

    /**
     * Listen for authentication state changes
     */
    onAuthStateChanged: function(callback) {
      if (typeof callback !== 'function') {
        throw new Error('onAuthStateChanged requires a function callback');
      }

      const id = _generateId();
      _authStateListeners[id] = callback;

      // Call immediately with current state
      setTimeout(() => callback(_user), 0);

      // Return unsubscribe function
      return function() {
        delete _authStateListeners[id];
      };
    },

    /**
     * Initialize a sign-in button
     */
    initSignInButton: function(selector, options) {
      _initSignInButton(selector, options);
      return this;
    }
  };

  // Expose to window
  window.EvrmoreAccounts = EvrmoreAccounts;

})(window); 