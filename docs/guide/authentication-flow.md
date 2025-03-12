# Authentication Flow

This page explains the authentication flow used by Evrmore Accounts.

## Overview

Evrmore Accounts uses a challenge-response authentication mechanism based on cryptographic signatures. This approach leverages the security of the Evrmore blockchain without requiring users to share their private keys.

## Authentication Steps

The authentication process follows these steps:

1. **Challenge Generation**: The server generates a unique challenge for the user's Evrmore address
2. **Challenge Signing**: The user signs the challenge with their private key
3. **Signature Verification**: The server verifies the signature against the user's public key
4. **Token Issuance**: Upon successful verification, the server issues a JWT token
5. **Session Management**: The client stores the token and uses it for subsequent requests

## Detailed Flow

### 1. Challenge Generation

When a user wants to authenticate, the client sends the user's Evrmore address to the server:

```
POST /api/challenge
{
  "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
}
```

The server generates a unique challenge string that includes:
- A fixed prefix
- The user's Evrmore address
- A timestamp
- A random nonce

Example challenge:
```
Sign this message to authenticate with Evrmore: EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc:1741815113:c4365fe48492d73f
```

### 2. Challenge Signing

The user signs this challenge with their private key. This can be done using:
- The Evrmore Core wallet
- A compatible wallet application
- The `evrmore-cli` command-line tool

Example using `evrmore-cli`:
```bash
evrmore-cli signmessage "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc" "Sign this message to authenticate with Evrmore: EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc:1741815113:c4365fe48492d73f"
```

This produces a base64-encoded signature.

### 3. Signature Verification

The client sends the signature back to the server along with the original challenge and Evrmore address:

```
POST /api/authenticate
{
  "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc",
  "challenge": "Sign this message to authenticate with Evrmore: EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc:1741815113:c4365fe48492d73f",
  "signature": "H9zHnUbwvQiXpAHnYDxkTRxCHRUKzQXQ3QNAyA+9SJKmEtFfMn7Z5JJXRQs29Jzf6HjA0e2yqC1Xk/9M94Uz6Sc="
}
```

The server verifies the signature using the Evrmore blockchain's signature verification algorithm. This confirms that the signature was created by the private key corresponding to the provided Evrmore address.

### 4. Token Issuance

If the signature is valid, the server:
1. Creates or retrieves the user account associated with the Evrmore address
2. Generates a JWT token containing the user's information and an expiration time
3. Returns the token to the client

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2025-03-19T13:41:53.198694",
  "user": {
    "id": "b95ab2dc-ef0a-4fc4-8404-dc6252c7bb53",
    "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
  }
}
```

### 5. Session Management

The client stores the token (typically in localStorage) and includes it in the Authorization header for subsequent API requests:

```
GET /api/user
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The server validates the token on each request and grants access to protected resources if the token is valid.

## Token Refresh

Tokens have an expiration time to enhance security. The client can:

1. Automatically refresh the token before it expires
2. Request a new token when the current one expires
3. Sign out the user when the token expires

## Security Considerations

This authentication flow provides several security benefits:

1. **Private Key Protection**: The user's private key never leaves their wallet
2. **Challenge Uniqueness**: Each challenge includes a timestamp and random nonce to prevent replay attacks
3. **Limited Challenge Lifetime**: Challenges expire after a short period (default: 10 minutes)
4. **Token Expiration**: JWT tokens have a limited lifetime
5. **Signature Verification**: The signature verification uses the same cryptographic algorithms as the Evrmore blockchain

## Next Steps

- Learn how to [configure](configuration.md) the authentication settings
- See [example integrations](../examples/basic.md) for implementation details
- Explore the [JavaScript library](../api/javascript.md) for client-side authentication 