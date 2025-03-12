# Troubleshooting Guide

This guide provides solutions for common issues you might encounter when using Evrmore Accounts.

## API Server Issues

### Server Won't Start

**Symptoms:**
- Error messages when starting the server
- Server crashes immediately after starting

**Possible Causes and Solutions:**

1. **Port Already in Use**
   ```
   Error: Address already in use
   ```
   
   **Solution:** Another application is using port 5000. Either:
   - Stop the other application
   - Change the port by setting the `PORT` environment variable:
     ```bash
     export PORT=5001
     python3 -m evrmore_accounts.app
     ```

2. **Missing Dependencies**
   ```
   ModuleNotFoundError: No module named 'flask'
   ```
   
   **Solution:** Install all required dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Invalid Configuration**
   ```
   KeyError: 'JWT_SECRET'
   ```
   
   **Solution:** Ensure all required environment variables are set:
   ```bash
   export JWT_SECRET=your_secure_secret
   export JWT_EXPIRATION=3600
   ```

### Database Issues

**Symptoms:**
- Error messages related to SQLite
- Authentication failures despite correct signatures

**Possible Causes and Solutions:**

1. **Database Permission Issues**
   ```
   sqlite3.OperationalError: unable to open database file
   ```
   
   **Solution:** Ensure the application has write permissions to the data directory:
   ```bash
   chmod 755 evrmore_accounts/data
   ```

2. **Corrupted Database**
   
   **Solution:** Backup and recreate the database:
   ```bash
   mv evrmore_accounts/data/users.db evrmore_accounts/data/users.db.bak
   # Restart the application to create a new database
   ```

## Authentication Issues

### Challenge Generation Fails

**Symptoms:**
- Error when requesting a challenge
- Empty or invalid challenge response

**Possible Causes and Solutions:**

1. **Invalid Evrmore Address**
   ```
   {"error": "Invalid Evrmore address format"}
   ```
   
   **Solution:** Ensure you're using a valid Evrmore address format (starting with 'E').

2. **Server Configuration Issues**
   
   **Solution:** Check server logs for specific errors and ensure all environment variables are correctly set.

### Authentication Fails

**Symptoms:**
- Authentication fails despite providing a valid signature
- Error messages during authentication

**Possible Causes and Solutions:**

1. **Expired Challenge**
   ```
   {"error": "Challenge expired"}
   ```
   
   **Solution:** Challenges expire after 5 minutes. Request a new challenge and complete authentication promptly.

2. **Invalid Signature**
   ```
   {"error": "Invalid signature"}
   ```
   
   **Solution:** 
   - Ensure you're signing the exact challenge string provided
   - Verify you're using the correct private key for the address
   - Check that the signature format is correct

3. **Clock Synchronization**
   
   **Solution:** Ensure your server's clock is synchronized correctly:
   ```bash
   sudo ntpdate pool.ntp.org
   ```

## JavaScript Client Issues

### Library Not Loading

**Symptoms:**
- Console errors about missing library
- `EvrmoreAccounts is not defined` errors

**Possible Causes and Solutions:**

1. **Incorrect Path**
   
   **Solution:** Verify the path to the JavaScript file:
   ```html
   <script src="/evrmore_accounts/static/evrmore-accounts.js"></script>
   ```

2. **CORS Issues**
   
   **Solution:** Check browser console for CORS errors and ensure your server is configured to allow requests from your domain.

### Authentication Flow Issues

**Symptoms:**
- Authentication process starts but doesn't complete
- No callback functions triggered

**Possible Causes and Solutions:**

1. **Incorrect API URL**
   
   **Solution:** Ensure you're providing the correct API URL when initializing:
   ```javascript
   const evrmoreAccounts = new EvrmoreAccounts({
     apiUrl: 'http://your-server:5000/api'
   });
   ```

2. **Missing Event Handlers**
   
   **Solution:** Verify you've set up all required event handlers:
   ```javascript
   evrmoreAccounts.on('authenticated', (user) => {
     console.log('User authenticated:', user);
   });
   
   evrmoreAccounts.on('error', (error) => {
     console.error('Authentication error:', error);
   });
   ```

## Docker Deployment Issues

### Container Won't Start

**Symptoms:**
- Container exits immediately after starting
- Error messages in Docker logs

**Possible Causes and Solutions:**

1. **Missing Environment Variables**
   
   **Solution:** Ensure all required environment variables are provided:
   ```bash
   docker run -p 5000:5000 \
     -e JWT_SECRET=your_secure_secret \
     -e JWT_EXPIRATION=3600 \
     evrmore-accounts
   ```

2. **Port Conflicts**
   
   **Solution:** If port 5000 is already in use, map to a different port:
   ```bash
   docker run -p 8080:5000 evrmore-accounts
   ```

### Container Starts But API Unreachable

**Symptoms:**
- Container appears to be running
- Cannot connect to API endpoints

**Possible Causes and Solutions:**

1. **Incorrect Host Configuration**
   
   **Solution:** Ensure the application is binding to 0.0.0.0 instead of localhost:
   ```bash
   docker run -p 5000:5000 -e HOST=0.0.0.0 evrmore-accounts
   ```

## Still Having Issues?

If you're still experiencing problems after trying these solutions:

1. Check the application logs for detailed error messages:
   ```bash
   python3 -m evrmore_accounts.app --debug
   ```

2. Open an issue on our [GitHub repository](https://github.com/manticoretechnologies/evrmore-accounts/issues) with:
   - Detailed description of the issue
   - Steps to reproduce
   - Error messages and logs
   - Your environment details (OS, Python version, etc.)

3. Contact our support team at dev@manticore.technology 