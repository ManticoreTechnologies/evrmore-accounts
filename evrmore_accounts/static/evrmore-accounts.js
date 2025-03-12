/**
 * Evrmore Accounts JavaScript Library
 * 
 * This library provides client-side functionality for Evrmore-based authentication,
 * including challenge generation, authentication, and token management.
 * 
 * @version 1.0.0
 * @author Manticore Technologies <dev@manticore.technology>
 */

(function() {
  'use strict';

  // Library namespace
  const EvrmoreAccounts = {};
  
  // Configuration
  const CONFIG = {
    apiUrl: '/api',
    autoRefresh: true,
    debug: false
  };
  
  // State
  const STATE = {
    authenticated: false,
    token: null,
    tokenExpires: null,
    user: null,
    refreshTimer: null,
    eventListeners: {},
    challengeData: null
  };
  
  // Local storage keys
  const STORAGE = {
    TOKEN: 'evrmore_accounts_token',
    TOKEN_EXPIRES: 'evrmore_accounts_token_expires',
    USER: 'evrmore_accounts_user'
  };
  
  /**
   * Initialize the library with configuration options
   * 
   * @param {Object} options - Configuration options
   * @param {string} options.apiUrl - API endpoint URL (default: '/api')
   * @param {boolean} options.autoRefresh - Auto-refresh authentication (default: true)
   * @param {boolean} options.debug - Enable debug logging (default: false)
   * @returns {Object} EvrmoreAccounts instance
   */
  EvrmoreAccounts.init = function(options = {}) {
    // Apply configuration options
    Object.assign(CONFIG, options);
    
    // Initialize from local storage
    _loadFromStorage();
    
    // Log initialization
    _log('EvrmoreAccounts initialized', CONFIG);
    
    // Check and validate token if one exists
    if (STATE.token) {
      _validateToken(STATE.token)
        .then(() => {
          _log('Existing token is valid');
        })
        .catch(err => {
          _log('Existing token is invalid, clearing authentication', err);
          _clearAuthentication();
        });
    }
    
    return EvrmoreAccounts;
  };
  
  /**
   * Configure the library
   * 
   * @param {Object} options - Configuration options
   * @returns {Object} EvrmoreAccounts instance
   */
  EvrmoreAccounts.configure = function(options = {}) {
    Object.assign(CONFIG, options);
    _log('Configuration updated', CONFIG);
    return EvrmoreAccounts;
  };
  
  /**
   * Check if the user is authenticated
   * 
   * @returns {boolean} Authentication status
   */
  EvrmoreAccounts.isAuthenticated = function() {
    return STATE.authenticated && STATE.token && new Date() < new Date(STATE.tokenExpires);
  };
  
  /**
   * Get the authenticated user information
   * 
   * @returns {Object|null} User information or null if not authenticated
   */
  EvrmoreAccounts.getUser = function() {
    return EvrmoreAccounts.isAuthenticated() ? STATE.user : null;
  };
  
  /**
   * Get the authentication token
   * 
   * @returns {string|null} Authentication token or null if not authenticated
   */
  EvrmoreAccounts.getToken = function() {
    return EvrmoreAccounts.isAuthenticated() ? STATE.token : null;
  };
  
  /**
   * Sign in with Evrmore wallet
   * 
   * @param {string} evrmoreAddress - Evrmore wallet address
   * @returns {Promise<Object>} Promise resolving to challenge data
   */
  EvrmoreAccounts.signIn = async function(evrmoreAddress) {
    if (!evrmoreAddress) {
      const error = new Error('Evrmore address is required');
      console.error('Evrmore Accounts: Sign-in error -', error);
      throw error;
    }
    
    _log('Starting sign-in flow for', evrmoreAddress);
    console.log('Evrmore Accounts: Starting sign-in flow for', evrmoreAddress);
    
    try {
      // Generate a challenge
      const challenge = await _generateChallenge(evrmoreAddress);
      _log('Challenge generated', challenge);
      console.log('Evrmore Accounts: Challenge generated', challenge);
      
      // Store challenge data for later
      STATE.challengeData = {
        address: evrmoreAddress,
        challenge: challenge.challenge
      };
      
      // Return the challenge to be signed
      return challenge;
    } catch (error) {
      console.error('Evrmore Accounts: Error generating challenge -', error);
      throw error;
    }
  };
  
  /**
   * Complete authentication with a signed challenge
   * 
   * @param {Object} authData - Authentication data
   * @param {string} authData.evrmoreAddress - Evrmore wallet address
   * @param {string} authData.challenge - Challenge text
   * @param {string} authData.signature - Signature of the challenge
   * @returns {Promise<Object>} Promise resolving to user information
   */
  EvrmoreAccounts.authenticate = async function(authData) {
    if (!authData.evrmoreAddress || !authData.challenge || !authData.signature) {
      const error = new Error('Evrmore address, challenge, and signature are required');
      console.error('Evrmore Accounts: Authentication error -', error);
      throw error;
    }
    
    _log('Authenticating with signed challenge', authData);
    console.log('Evrmore Accounts: Authenticating with signed challenge', {
      evrmoreAddress: authData.evrmoreAddress,
      challenge: authData.challenge,
      signatureLength: authData.signature.length
    });
    
    try {
      // Make authentication request
      console.log('Evrmore Accounts: Sending authentication request to', `${CONFIG.apiUrl}/authenticate`);
      const response = await fetch(`${CONFIG.apiUrl}/authenticate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          evrmore_address: authData.evrmoreAddress,
          challenge: authData.challenge,
          signature: authData.signature
        })
      });
      
      // Check response
      if (!response.ok) {
        const error = await response.json();
        console.error('Evrmore Accounts: Server returned error', error);
        throw new Error(error.error || 'Authentication failed');
      }
      
      // Process successful authentication
      const authResult = await response.json();
      _log('Authentication successful', authResult);
      console.log('Evrmore Accounts: Authentication successful', authResult);
      
      // Store authentication data
      _setAuthentication(authResult.token, authResult.expires_at, authResult.user);
      
      // Clear challenge data
      STATE.challengeData = null;
      
      return authResult.user;
    } catch (err) {
      _log('Authentication error', err);
      console.error('Evrmore Accounts: Authentication error', err);
      throw err;
    }
  };
  
  /**
   * Sign out
   * 
   * @returns {Promise<void>} Promise resolving when sign-out is complete
   */
  EvrmoreAccounts.signOut = async function() {
    _log('Signing out');
    
    if (STATE.token) {
      try {
        // Call logout endpoint if authenticated
        await fetch(`${CONFIG.apiUrl}/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${STATE.token}`,
            'Content-Type': 'application/json'
          }
        });
      } catch (err) {
        _log('Error during logout', err);
        // Continue with local sign-out even if API call fails
      }
    }
    
    // Clear local authentication data
    _clearAuthentication();
    
    return Promise.resolve();
  };
  
  /**
   * Add a listener for authentication state changes
   * 
   * @param {Function} callback - Callback function receiving the user object or null
   * @returns {Function} Function to remove the listener
   */
  EvrmoreAccounts.onAuthStateChanged = function(callback) {
    if (typeof callback !== 'function') {
      throw new Error('Callback must be a function');
    }
    
    const id = _generateId();
    STATE.eventListeners[id] = callback;
    
    // Immediately invoke with current state
    setTimeout(() => {
      callback(EvrmoreAccounts.isAuthenticated() ? STATE.user : null);
    }, 0);
    
    // Return function to remove listener
    return function() {
      delete STATE.eventListeners[id];
    };
  };
  
  /**
   * Initialize the sign-in button
   * 
   * @param {string|Element} buttonEl - Button element or selector
   * @param {Object} options - Options
   * @returns {Object} EvrmoreAccounts instance
   */
  EvrmoreAccounts.initSignInButton = function(buttonEl, options = {}) {
    const button = typeof buttonEl === 'string' 
      ? document.querySelector(buttonEl) 
      : buttonEl;
    
    if (!button) {
      _log('Sign-in button not found', buttonEl);
      console.error('Evrmore Accounts: Sign-in button not found', buttonEl);
      return EvrmoreAccounts;
    }
    
    _log('Initializing sign-in button', button);
    console.log('Evrmore Accounts: Initializing sign-in button', button);
    
    // Add click handler
    button.addEventListener('click', async function(e) {
      e.preventDefault();
      
      console.log('Evrmore Accounts: Sign-in button clicked');
      
      // Get Evrmore address
      let evrmoreAddress = options.evrmoreAddress;
      
      // If no address provided, prompt the user
      if (!evrmoreAddress) {
        evrmoreAddress = prompt('Enter your Evrmore address:');
        if (!evrmoreAddress) return;
      }
      
      console.log('Evrmore Accounts: Starting authentication for address', evrmoreAddress);
      
      try {
        // Generate challenge
        const challenge = await EvrmoreAccounts.signIn(evrmoreAddress);
        console.log('Evrmore Accounts: Challenge generated', challenge);
        
        // Store address in the challenge for later use
        challenge.address = evrmoreAddress;
        
        // Allow the app to handle the challenge process
        if (typeof options.onChallenge === 'function') {
          console.log('Evrmore Accounts: Using custom challenge handler');
          options.onChallenge(challenge, async (signature) => {
            if (signature) {
              console.log('Evrmore Accounts: Authenticating with signature');
              // Authenticate with the signature
              try {
                await EvrmoreAccounts.authenticate({
                  evrmoreAddress: evrmoreAddress,
                  challenge: challenge.challenge,
                  signature: signature
                });
              } catch (error) {
                console.error('Evrmore Accounts: Authentication error', error);
                throw error;
              }
            }
          });
        } else {
          // Default challenge flow - prompt for signature
          console.log('Evrmore Accounts: Using default challenge handler');
          const message = `Please sign this message with your Evrmore wallet:\n\n${challenge.challenge}`;
          alert(message);
          
          const signature = prompt('Enter your signature:');
          if (signature) {
            // Authenticate with the signature
            await EvrmoreAccounts.authenticate({
              evrmoreAddress: evrmoreAddress,
              challenge: challenge.challenge,
              signature: signature
            });
          }
        }
      } catch (err) {
        _log('Error in sign-in flow', err);
        alert(`Error: ${err.message}`);
      }
    });
    
    return EvrmoreAccounts;
  };
  
  /**
   * Generate a challenge for an Evrmore address
   * 
   * @param {string} evrmoreAddress - Evrmore wallet address
   * @returns {Promise<Object>} Promise resolving to challenge data
   * @private
   */
  async function _generateChallenge(evrmoreAddress) {
    console.log('Evrmore Accounts: Generating challenge for', evrmoreAddress, 'at', `${CONFIG.apiUrl}/challenge`);
    
    try {
      const response = await fetch(`${CONFIG.apiUrl}/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          evrmore_address: evrmoreAddress
        })
      });
      
      if (!response.ok) {
        const error = await response.json();
        console.error('Evrmore Accounts: Challenge generation failed', error);
        throw new Error(error.error || 'Failed to generate challenge');
      }
      
      const challenge = await response.json();
      console.log('Evrmore Accounts: Challenge received', challenge);
      return challenge;
    } catch (error) {
      console.error('Evrmore Accounts: Network error during challenge generation', error);
      throw error;
    }
  }
  
  /**
   * Validate a token with the server
   * 
   * @param {string} token - Token to validate
   * @returns {Promise<Object>} Promise resolving to validation result
   * @private
   */
  async function _validateToken(token) {
    const response = await fetch(`${CONFIG.apiUrl}/validate`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Invalid token');
    }
    
    return await response.json();
  }
  
  /**
   * Set authentication state
   * 
   * @param {string} token - Authentication token
   * @param {string} tokenExpires - Token expiration timestamp
   * @param {Object} user - User information
   * @private
   */
  function _setAuthentication(token, tokenExpires, user) {
    STATE.token = token;
    STATE.tokenExpires = tokenExpires;
    STATE.user = user;
    STATE.authenticated = true;
    
    // Save to local storage
    localStorage.setItem(STORAGE.TOKEN, token);
    localStorage.setItem(STORAGE.TOKEN_EXPIRES, tokenExpires);
    localStorage.setItem(STORAGE.USER, JSON.stringify(user));
    
    // Notify listeners
    _notifyListeners();
    
    // Setup auto-refresh if enabled
    if (CONFIG.autoRefresh) {
      _setupAutoRefresh();
    }
  }
  
  /**
   * Clear authentication state
   * 
   * @private
   */
  function _clearAuthentication() {
    STATE.token = null;
    STATE.tokenExpires = null;
    STATE.user = null;
    STATE.authenticated = false;
    
    // Clear from local storage
    localStorage.removeItem(STORAGE.TOKEN);
    localStorage.removeItem(STORAGE.TOKEN_EXPIRES);
    localStorage.removeItem(STORAGE.USER);
    
    // Clear refresh timer
    if (STATE.refreshTimer) {
      clearTimeout(STATE.refreshTimer);
      STATE.refreshTimer = null;
    }
    
    // Notify listeners
    _notifyListeners();
  }
  
  /**
   * Load authentication state from local storage
   * 
   * @private
   */
  function _loadFromStorage() {
    const token = localStorage.getItem(STORAGE.TOKEN);
    const tokenExpires = localStorage.getItem(STORAGE.TOKEN_EXPIRES);
    const user = localStorage.getItem(STORAGE.USER);
    
    if (token && tokenExpires && user) {
      try {
        const parsedUser = JSON.parse(user);
        const expiresDate = new Date(tokenExpires);
        
        // Check if token is still valid
        if (expiresDate > new Date()) {
          STATE.token = token;
          STATE.tokenExpires = tokenExpires;
          STATE.user = parsedUser;
          STATE.authenticated = true;
          
          _log('Loaded authentication from storage');
          
          // Validate token with the server
          _validateToken(token)
            .then(result => {
              _log('Server confirmed token is valid', result);
              // Update expiration if it changed
              if (result.expires_at) {
                STATE.tokenExpires = result.expires_at;
                localStorage.setItem(STORAGE.TOKEN_EXPIRES, result.expires_at);
              }
              
              // Setup auto-refresh if enabled
              if (CONFIG.autoRefresh) {
                _setupAutoRefresh();
              }
            })
            .catch(err => {
              _log('Server rejected token, clearing authentication', err);
              _clearAuthentication();
            });
          
          // Immediately setup auto-refresh if enabled to prevent expiration while validating
          if (CONFIG.autoRefresh) {
            _setupAutoRefresh();
          }
        } else {
          _log('Stored token is expired');
        }
      } catch (err) {
        _log('Error loading from storage', err);
      }
    }
  }
  
  /**
   * Setup auto-refresh for the token
   * 
   * @private
   */
  function _setupAutoRefresh() {
    // Clear existing timer
    if (STATE.refreshTimer) {
      clearTimeout(STATE.refreshTimer);
    }
    
    if (!STATE.token || !STATE.tokenExpires) {
      return;
    }
    
    // Calculate time until refresh (90% of the time until expiration)
    const expiresDate = new Date(STATE.tokenExpires);
    const now = new Date();
    const timeUntilExpire = expiresDate.getTime() - now.getTime();
    const refreshTime = timeUntilExpire * 0.9;
    
    // Only setup refresh if we have a reasonable amount of time left
    if (timeUntilExpire > 0 && refreshTime > 1000) {
      STATE.refreshTimer = setTimeout(() => {
        _validateToken(STATE.token)
          .catch(() => {
            _log('Token refresh failed, clearing authentication');
            _clearAuthentication();
          });
      }, refreshTime);
    }
  }
  
  /**
   * Notify listeners of authentication state changes
   * 
   * @private
   */
  function _notifyListeners() {
    const user = STATE.authenticated ? STATE.user : null;
    Object.values(STATE.eventListeners).forEach(callback => {
      try {
        callback(user);
      } catch (err) {
        _log('Error in auth state change listener', err);
      }
    });
  }
  
  /**
   * Generate a random ID
   * 
   * @returns {string} Random ID
   * @private
   */
  function _generateId() {
    return Math.random().toString(36).substring(2);
  }
  
  /**
   * Log a message if debug is enabled
   * 
   * @param {...any} args - Arguments to log
   * @private
   */
  function _log(...args) {
    if (CONFIG.debug) {
      console.log('[EvrmoreAccounts]', ...args);
    }
  }
  
  // Expose API
  if (typeof window !== 'undefined') {
    window.EvrmoreAccounts = EvrmoreAccounts;
  }
  
  // Support CommonJS and ES modules
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = EvrmoreAccounts;
  }
  
  if (typeof define === 'function' && define.amd) {
    define([], function() {
      return EvrmoreAccounts;
    });
  }
})(); 