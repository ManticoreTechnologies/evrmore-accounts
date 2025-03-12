# Security

This document outlines security considerations and best practices for deploying and using the Evrmore Accounts package in production environments.

## Security Model

Evrmore Accounts uses a blockchain-based authentication system that leverages cryptographic signatures to verify user identity. This approach eliminates the need for password storage and provides several security advantages:

- No passwords are stored, eliminating the risk of password database breaches
- Authentication relies on cryptographic signatures that cannot be forged without access to the private key
- Each authentication attempt uses a unique challenge, preventing replay attacks
- JWT tokens are used for session management with configurable expiration

## Production Deployment Recommendations

### Environment Configuration

1. **Use HTTPS**: Always deploy your application behind HTTPS in production. This prevents man-in-the-middle attacks and protects authentication tokens in transit.

2. **Secure JWT Secret**: Set a strong, unique `JWT_SECRET` environment variable for production deployments. This secret should be:
   - At least 32 characters long
   - Randomly generated
   - Kept confidential and not committed to source control

3. **Configure Token Expiration**: Set appropriate values for `JWT_EXPIRATION` and `REFRESH_TOKEN_EXPIRATION` based on your security requirements.

4. **Limit Access**: Use network-level controls to restrict access to your API server from trusted sources only.

### Docker Security

If using the provided Docker configuration:

1. **Use Non-Root User**: Modify the Dockerfile to run the application as a non-root user:
   ```dockerfile
   # Add after installing dependencies
   RUN adduser --disabled-password --gecos "" appuser
   USER appuser
   ```

2. **Pin Dependency Versions**: Ensure all dependencies in requirements.txt have pinned versions to prevent unexpected updates.

3. **Scan Images**: Regularly scan your Docker images for vulnerabilities using tools like Trivy or Docker Scout.

## API Security Considerations

1. **Rate Limiting**: Implement rate limiting on authentication endpoints to prevent brute force attacks.

2. **CORS Configuration**: Configure CORS headers to allow only trusted domains to access your API:
   ```python
   # In your app configuration
   CORS(app, resources={r"/api/*": {"origins": "https://yourtrustedapp.com"}})
   ```

3. **Validate Input**: Always validate and sanitize user input to prevent injection attacks.

## Client-Side Security

1. **Token Storage**: Store JWT tokens in memory or secure HTTP-only cookies rather than localStorage to mitigate XSS risks.

2. **Secure Communication**: Always use HTTPS for API calls from your client application.

3. **Content Security Policy**: Implement a strict Content Security Policy to prevent XSS attacks.

## Security Monitoring

1. **Logging**: Enable comprehensive logging for authentication attempts, including successful and failed attempts.

2. **Monitoring**: Set up monitoring for unusual authentication patterns that might indicate an attack.

3. **Alerts**: Configure alerts for multiple failed authentication attempts from the same IP address.

## Vulnerability Reporting

If you discover a security vulnerability in Evrmore Accounts, please report it by sending an email to security@manticore.technology. Please do not disclose security vulnerabilities publicly until they have been addressed by our team.

## Security Updates

Stay informed about security updates by:

1. Watching the GitHub repository
2. Subscribing to our security mailing list
3. Regularly updating to the latest version of Evrmore Accounts

## Regular Security Audits

We recommend conducting regular security audits of your implementation, focusing on:

1. Token handling and storage
2. API endpoint security
3. Input validation
4. Dependency vulnerabilities

## Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/) 