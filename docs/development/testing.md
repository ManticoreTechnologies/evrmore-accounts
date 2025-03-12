# Testing Evrmore Accounts

This guide explains how to test the Evrmore Accounts package during development.

## Setting Up the Test Environment

Before running tests, you need to set up your development environment:

```bash
# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package in development mode with test dependencies
pip3 install -e ".[dev]"
```

## Running Tests

We use pytest for testing. To run all tests:

```bash
pytest
```

To run tests with coverage information:

```bash
pytest --cov=evrmore_accounts
```

To generate a coverage report:

```bash
pytest --cov=evrmore_accounts --cov-report=html
```

This will generate an HTML coverage report in the `htmlcov` directory.

## Test Structure

Tests are organized in the `tests` directory with the following structure:

```
tests/
├── conftest.py         # Shared fixtures
├── test_api/           # API tests
│   ├── test_auth.py    # Authentication tests
│   └── test_server.py  # Server tests
├── test_app.py         # Application tests
└── test_integration.py # Integration tests
```

## Writing Tests

When writing tests, follow these guidelines:

1. **Use fixtures**: Create reusable fixtures in `conftest.py`
2. **Test one thing at a time**: Each test should focus on a single functionality
3. **Use descriptive names**: Test names should describe what they're testing
4. **Mock external dependencies**: Use pytest's monkeypatch or unittest.mock

Example test:

```python
def test_generate_challenge(client):
    """Test challenge generation endpoint."""
    response = client.post(
        "/api/challenge",
        json={"evrmore_address": "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"}
    )
    
    assert response.status_code == 200
    data = response.json
    assert "challenge" in data
    assert "expires_at" in data
```

## Test Fixtures

We provide several fixtures in `conftest.py` to help with testing:

- `app`: Flask application instance
- `client`: Flask test client
- `auth`: AccountsAuth instance
- `server`: AccountsServer instance
- `test_address`: Test Evrmore address
- `test_challenge`: Test challenge
- `test_signature`: Test signature

Example usage:

```python
def test_authenticate(client, test_address, test_challenge, test_signature):
    """Test authentication endpoint."""
    response = client.post(
        "/api/authenticate",
        json={
            "evrmore_address": test_address,
            "challenge": test_challenge,
            "signature": test_signature
        }
    )
    
    assert response.status_code == 200
    data = response.json
    assert "token" in data
    assert "expires_at" in data
    assert "user" in data
```

## Mocking

For tests that require mocking external dependencies, use pytest's monkeypatch or unittest.mock:

```python
def test_validate_token_with_mock(monkeypatch, auth):
    """Test token validation with mocked EvrmoreAuth."""
    
    # Create a mock object
    class MockTokenData:
        expires_at = "2025-03-19T13:41:53.198694"
        evrmore_address = "EViF16aYCetDH56MyKCcxfyeZ3F7Ao7ZBc"
    
    # Mock the validate_token method
    def mock_validate_token(token):
        return MockTokenData()
    
    # Apply the mock
    monkeypatch.setattr(auth.auth, "validate_token", mock_validate_token)
    
    # Test the method
    result = auth.validate_token("fake_token")
    
    assert result["valid"] is True
    assert result["expires_at"] == MockTokenData.expires_at
    assert result["evrmore_address"] == MockTokenData.evrmore_address
```

## Integration Testing

Integration tests verify that different components work together correctly. These tests typically involve:

1. Starting the server
2. Making HTTP requests
3. Verifying the responses

Example integration test:

```python
def test_full_authentication_flow(client, test_address):
    """Test the full authentication flow."""
    # 1. Generate challenge
    challenge_response = client.post(
        "/api/challenge",
        json={"evrmore_address": test_address}
    )
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json
    challenge = challenge_data["challenge"]
    
    # 2. Sign challenge (mocked in this example)
    signature = "H9zHnUbwvQiXpAHnYDxkTRxCHRUKzQXQ3QNAyA+9SJKmEtFfMn7Z5JJXRQs29Jzf6HjA0e2yqC1Xk/9M94Uz6Sc="
    
    # 3. Authenticate
    auth_response = client.post(
        "/api/authenticate",
        json={
            "evrmore_address": test_address,
            "challenge": challenge,
            "signature": signature
        }
    )
    assert auth_response.status_code == 200
    auth_data = auth_response.json
    token = auth_data["token"]
    
    # 4. Validate token
    validate_response = client.get(
        "/api/validate",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert validate_response.status_code == 200
    validate_data = validate_response.json
    assert validate_data["valid"] is True
    
    # 5. Get user info
    user_response = client.get(
        "/api/user",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert user_response.status_code == 200
    user_data = user_response.json
    assert user_data["evrmore_address"] == test_address
    
    # 6. Logout
    logout_response = client.post(
        "/api/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_response.status_code == 200
    logout_data = logout_response.json
    assert logout_data["success"] is True
```

## JavaScript Testing

For testing the JavaScript client library, we use Jest. To run JavaScript tests:

```bash
# Install dependencies
npm install

# Run tests
npm test
```

## Continuous Integration

We use GitHub Actions for continuous integration. The CI pipeline runs tests on multiple Python versions to ensure compatibility.

You can see the CI configuration in the `.github/workflows/tests.yml` file.

## Test Coverage

We aim for high test coverage to ensure code quality. You can check the current coverage with:

```bash
pytest --cov=evrmore_accounts
```

## Next Steps

- Learn about [contributing](contributing.md) to the project
- Explore the [API reference](../api/backend.md) 