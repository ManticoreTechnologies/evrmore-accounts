# Backend API Reference

This page documents the RESTful API endpoints provided by Evrmore Accounts.

## API Endpoints Overview

All API endpoints are prefixed with `/api`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenge` | POST | Generate a challenge for a user |
| `/authenticate` | POST | Authenticate with a signed challenge |
| `/validate` | GET | Validate a JWT token |
| `/user` | GET | Get authenticated user information |
| `/logout` | POST | Invalidate a JWT token (logout) |
| `/health` | GET | Check API health status |

## Challenge Generation

Generates a challenge for a user to sign with their Evrmore wallet.

```
POST /api/challenge
```

### Request Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `evrmore_address` | string | The Evrmore address for the user |
| `expire_minutes` | integer | (Optional) Minutes until the challenge expires (default: 10) |

### Example Request

```json
{
  "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
}
```

### Example Response

```json
{
  "challenge": "Sign this message to authenticate with Evrmore: EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc:1741815113:c4365fe48492d73f",
  "expires_at": "2025-03-12T13:41:53.198694"
}
```

### Error Responses

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Missing parameters |
| 500 | Server Error |

## Authentication

Authenticates a user with a signed challenge.

```
POST /api/authenticate
```

### Request Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `evrmore_address` | string | The Evrmore address for the user |
| `challenge` | string | The challenge text previously generated |
| `signature` | string | The signature created by signing the challenge with the user's wallet |

### Example Request

```json
{
  "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc",
  "challenge": "Sign this message to authenticate with Evrmore: EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc:1741815113:c4365fe48492d73f",
  "signature": "H9zHnUbwvQiXpAHnYDxkTRxCHRUKzQXQ3QNAyA+9SJKmEtFfMn7Z5JJXRQs29Jzf6HjA0e2yqC1Xk/9M94Uz6Sc="
}
```

### Example Response

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

### Error Responses

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Missing parameters |
| 401 | Unauthorized - Invalid signature |
| 500 | Server Error |

## Token Validation

Validates a JWT token.

```
GET /api/validate
```

### Request Headers

| Header | Description |
|--------|-------------|
| `Authorization` | Bearer token (format: `Bearer <token>`) |

### Example Response

```json
{
  "valid": true,
  "expires_at": "2025-03-19T13:41:53.198694",
  "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
}
```

### Error Responses

| Status Code | Description |
|-------------|-------------|
| 401 | Unauthorized - Invalid or missing token |
| 500 | Server Error |

## User Information

Gets information about the authenticated user.

```
GET /api/user
```

### Request Headers

| Header | Description |
|--------|-------------|
| `Authorization` | Bearer token (format: `Bearer <token>`) |

### Example Response

```json
{
  "id": "b95ab2dc-ef0a-4fc4-8404-dc6252c7bb53",
  "evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc",
  "username": null,
  "email": null,
  "is_active": true
}
```

### Error Responses

| Status Code | Description |
|-------------|-------------|
| 401 | Unauthorized - Invalid or missing token |
| 500 | Server Error |

## Logout

Invalidates a JWT token (logs out the user).

```
POST /api/logout
```

### Request Headers

| Header | Description |
|--------|-------------|
| `Authorization` | Bearer token (format: `Bearer <token>`) |

### Example Response

```json
{
  "success": true,
  "message": "Successfully logged out"
}
```

### Error Responses

| Status Code | Description |
|-------------|-------------|
| 401 | Unauthorized - Invalid or missing token |
| 500 | Server Error |

## Health Check

Checks the health status of the API.

```
GET /api/health
```

### Example Response

```json
{
  "status": "ok",
  "timestamp": "2025-03-12T13:41:53.198694",
  "version": "1.0.0"
}
``` 