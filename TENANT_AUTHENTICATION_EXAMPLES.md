# Complete Tenant Authentication Flow - Technical Guide

A comprehensive guide demonstrating the complete tenant authentication flow implementation. This document shows how tenants authenticate first using client credentials, then use their tokens to authenticate their users.

## Table of Contents

- [Overview](#overview)
- [Authentication Flow Architecture](#authentication-flow-architecture)
- [Implementation Examples](#implementation-examples)
- [Client SDK Examples](#client-sdk-examples)
- [Security Implementation](#security-implementation)
- [HTTP Response Reference](#http-response-reference)
- [Related Documentation](#related-documentation)

## Overview

The tenant authentication system provides a secure, two-phase authentication process. First, tenants authenticate themselves to get access tokens. Then, they use these tokens to authenticate their users. This approach ensures complete isolation between tenants while maintaining security.

## Authentication Flow Architecture

### Step 1: Tenant Authentication
Tenant authenticates using client credentials and receives a tenant access token

### Step 2: User Authentication  
Tenant uses tenant token to authenticate their users, and users receive user tokens

### Step 3: API Access
Users use their tokens to access tenant-scoped resources

## Implementation Examples

### 1. Tenant Authentication

Start by authenticating your tenant to get an access token:

**Request:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/tenant/auth \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "client-1234567890",
    "client_secret": "secret-1234567890",
    "grant_type": "client_credentials"
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ0ZW5hbnQiLCJzY29wZSI6InRlbmFudDpyZWFkIHRlbmFudDp3cml0ZSB1c2VyOnJlYWQgdXNlcjp3cml0ZSIsImlhdCI6MTcwMzEyMzQ1NiwiZXhwIjoxNzAzMTI3MDU2fQ.abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "scope": "tenant:read tenant:write user:read user:write",
  "tenant_id": "tenant-1234567890",
  "tenant_name": "Example Corp"
}
```

**Error Responses:**

**400 Bad Request - Invalid grant type:**
```json
{
  "error": "unsupported_grant_type",
  "message": "Only client_credentials grant type is supported"
}
```

**401 Unauthorized - Invalid credentials:**
```json
{
  "error": "authentication_failed",
  "message": "invalid client credentials"
}
```

**403 Forbidden - Tenant suspended:**
```json
{
  "error": "authentication_failed",
  "message": "tenant access denied: tenant is suspended"
}
```

### 2. User Authentication (Using Tenant Token)

Once you have a tenant token, use it to authenticate users:

**Request:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ0ZW5hbnQiLCJzY29wZSI6InRlbmFudDpyZWFkIHRlbmFudDp3cml0ZSB1c2VyOnJlYWQgdXNlcjp3cml0ZSIsImlhdCI6MTcwMzEyMzQ1NiwiZXhwIjoxNzAzMTI3MDU2fQ.abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci0xMjMiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ1c2VyIiwicm9sZXMiOlsidXNlciJdLCJpYXQiOjE3MDMxMjM0NTYsImV4cCI6MTcwMzEyNzA1Nn0.xyz789...",
  "refresh_token": "user-refresh-token-123",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "user-123",
    "email": "user@example.com",
    "tenant_id": "tenant-1234567890",
    "roles": [
      {
        "id": "role-1",
        "name": "user"
      }
    ]
  },
  "tenant": {
    "id": "tenant-1234567890",
    "name": "Example Corp",
    "domain": "example.com"
  }
}
```

**Error Responses:**

**400 Bad Request - Missing tenant ID:**
```json
{
  "error": "missing_tenant_id",
  "message": "Tenant ID is required"
}
```

**401 Unauthorized - Invalid tenant token:**
```json
{
  "error": "tenant_access_denied",
  "message": "invalid token"
}
```

**403 Forbidden - Tenant suspended:**
```json
{
  "error": "tenant_access_denied",
  "message": "tenant is suspended"
}
```

### 3. Token Validation

Validate tokens to ensure they're still active:

**Request:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/tenant/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ0ZW5hbnQiLCJzY29wZSI6InRlbmFudDpyZWFkIHRlbmFudDp3cml0ZSB1c2VyOnJlYWQgdXNlcjp3cml0ZSIsImlhdCI6MTcwMzEyMzQ1NiwiZXhwIjoxNzAzMTI3MDU2fQ.abc123..."
  }'
```

**Response (200 OK):**
```json
{
  "tenant_id": "tenant-1234567890",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_at": "2023-12-21T15:00:56Z",
  "scope": "tenant:read tenant:write user:read user:write",
  "created_at": "2023-12-21T14:00:56Z"
}
```

### 4. Token Refresh

Keep your sessions active by refreshing tokens before they expire:

**Request:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/tenant/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ0ZW5hbnQiLCJzY29wZSI6InRlbmFudDpyZWFkIHRlbmFudDp3cml0ZSB1c2VyOnJlYWQgdXNlcjp3cml0ZSIsImlhdCI6MTcwMzEyMzQ1NiwiZXhwIjoxNzAzMTI3MDU2fQ.new123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new-refresh-token-456",
  "scope": "tenant:read tenant:write user:read user:write",
  "tenant_id": "tenant-1234567890",
  "tenant_name": "Example Corp"
}
```

### 5. Token Revocation

Securely log out by revoking tokens:

**Request:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/tenant/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ0ZW5hbnQiLCJzY29wZSI6InRlbmFudDpyZWFkIHRlbmFudDp3cml0ZSB1c2VyOnJlYWQgdXNlcjp3cml0ZSIsImlhdCI6MTcwMzEyMzQ1NiwiZXhwIjoxNzAzMTI3MDU2fQ.abc123..."
  }'
```

**Response (200 OK):**
```json
{
  "message": "Token revoked successfully"
}
```

### 6. Get Tenant Information

Retrieve detailed information about your tenant:

**Request:**
```bash
curl -X GET https://auth.yourdomain.com/api/v1/tenant/info \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDU2Nzg5MCIsInR5cGUiOiJ0ZW5hbnQiLCJzY29wZSI6InRlbmFudDpyZWFkIHRlbmFudDp3cml0ZSB1c2VyOnJlYWQgdXNlcjp3cml0ZSIsImlhdCI6MTcwMzEyMzQ1NiwiZXhwIjoxNzAzMTI3MDU2fQ.abc123..."
```

**Response (200 OK):**
```json
{
  "id": "tenant-1234567890",
  "name": "Example Corp",
  "domain": "example.com",
  "status": "active",
  "client_id": "client-1234567890",
  "settings": {
    "allowed_origins": ["https://example.com"],
    "custom_branding": true,
    "enable_oauth": true,
    "enable_mfa": true,
    "session_timeout": 60,
    "max_login_attempts": 10,
    "enable_audit_log": true,
    "password_policy": {
      "min_length": 10,
      "require_upper": true,
      "require_lower": true,
      "require_numbers": true,
      "require_special": true,
      "max_age": 60
    }
  },
  "created_at": "2023-12-01T10:00:00Z",
  "updated_at": "2023-12-21T14:00:00Z"
}
```

## Client SDK Examples

### JavaScript and TypeScript Client

Here's a complete client implementation for JavaScript applications:

```javascript
class TenantAuthClient {
  constructor(baseURL, clientID, clientSecret) {
    this.baseURL = baseURL;
    this.clientID = clientID;
    this.clientSecret = clientSecret;
    this.tenantToken = null;
  }

  // Step 1: Authenticate tenant
  async authenticateTenant() {
    const response = await fetch(`${this.baseURL}/api/v1/tenant/auth`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: this.clientID,
        client_secret: this.clientSecret,
        grant_type: 'client_credentials'
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Tenant authentication failed: ${error.message}`);
    }

    const data = await response.json();
    this.tenantToken = data.access_token;
    return data;
  }

  // Step 2: Authenticate user within tenant
  async authenticateUser(email, password) {
    if (!this.tenantToken) {
      throw new Error('Tenant not authenticated. Call authenticateTenant() first.');
    }

    const response = await fetch(`${this.baseURL}/api/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.tenantToken}`
      },
      body: JSON.stringify({
        email,
        password
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`User authentication failed: ${error.message}`);
    }

    return await response.json();
  }

  // Step 3: Make authenticated API calls
  async makeAuthenticatedCall(endpoint, userToken) {
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${userToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`API call failed: ${error.message}`);
    }

    return await response.json();
  }

  // Refresh tenant token
  async refreshTenantToken(refreshToken) {
    const response = await fetch(`${this.baseURL}/api/v1/tenant/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        refresh_token: refreshToken
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Token refresh failed: ${error.message}`);
    }

    const data = await response.json();
    this.tenantToken = data.access_token;
    return data;
  }
}

// Usage example
async function example() {
  const client = new TenantAuthClient(
    'https://auth.yourdomain.com',
    'client-1234567890',
    'secret-1234567890'
  );

  try {
    // Step 1: Authenticate tenant
    const tenantAuth = await client.authenticateTenant();
    console.log('Tenant authenticated:', tenantAuth.tenant_name);

    // Step 2: Authenticate user
    const userAuth = await client.authenticateUser('user@example.com', 'password123');
    console.log('User authenticated:', userAuth.user.email);

    // Step 3: Make API calls
    const userProfile = await client.makeAuthenticatedCall('/api/v1/user/profile', userAuth.access_token);
    console.log('User profile:', userProfile);

  } catch (error) {
    console.error('Authentication error:', error.message);
  }
}
```

### Python Client

Here's a Python implementation for backend services:

```python
import requests
import json

class TenantAuthClient:
    def __init__(self, base_url, client_id, client_secret):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_token = None

    def authenticate_tenant(self):
        """Step 1: Authenticate tenant"""
        response = requests.post(
            f"{self.base_url}/api/v1/tenant/auth",
            headers={"Content-Type": "application/json"},
            json={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials"
            }
        )

        if not response.ok:
            error = response.json()
            raise Exception(f"Tenant authentication failed: {error['message']}")

        data = response.json()
        self.tenant_token = data["access_token"]
        return data

    def authenticate_user(self, email, password):
        """Step 2: Authenticate user within tenant"""
        if not self.tenant_token:
            raise Exception("Tenant not authenticated. Call authenticate_tenant() first.")

        response = requests.post(
            f"{self.base_url}/api/v1/auth/login",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.tenant_token}"
            },
            json={"email": email, "password": password}
        )

        if not response.ok:
            error = response.json()
            raise Exception(f"User authentication failed: {error['message']}")

        return response.json()

    def make_authenticated_call(self, endpoint, user_token):
        """Step 3: Make authenticated API calls"""
        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers={
                "Authorization": f"Bearer {user_token}",
                "Content-Type": "application/json"
            }
        )

        if not response.ok:
            error = response.json()
            raise Exception(f"API call failed: {error['message']}")

        return response.json()

# Usage example
def example():
    client = TenantAuthClient(
        "https://auth.yourdomain.com",
        "client-1234567890",
        "secret-1234567890"
    )

    try:
        # Step 1: Authenticate tenant
        tenant_auth = client.authenticate_tenant()
        print(f"Tenant authenticated: {tenant_auth['tenant_name']}")

        # Step 2: Authenticate user
        user_auth = client.authenticate_user("user@example.com", "password123")
        print(f"User authenticated: {user_auth['user']['email']}")

        # Step 3: Make API calls
        user_profile = client.make_authenticated_call("/api/v1/user/profile", user_auth["access_token"])
        print(f"User profile: {user_profile}")

    except Exception as e:
        print(f"Authentication error: {e}")
```

## Security Implementation

### Token Security
- Tenant tokens have 1-hour expiration by default
- User tokens have configurable expiration per tenant
- Refresh tokens are cryptographically secure
- All tokens are validated on every request

### Tenant Isolation
- Complete data isolation per tenant
- Tenant tokens can only access their own resources
- User tokens are scoped to specific tenant

### Rate Limiting
- Tenant authentication is rate-limited to prevent abuse
- User authentication is rate-limited per tenant
- API calls are rate-limited per tenant

### Audit Logging
- All authentication events are logged
- Failed authentication attempts are tracked
- Token usage is monitored for security analysis

## HTTP Response Reference

| Status | Scenario | Error Code | Description |
|--------|----------|------------|-------------|
| 200 | Success | - | Operation completed successfully |
| 400 | Bad Request | `invalid_request` | Invalid request body or parameters |
| 400 | Bad Request | `unsupported_grant_type` | Unsupported OAuth grant type |
| 400 | Bad Request | `missing_tenant_id` | Tenant ID not provided |
| 401 | Unauthorized | `authentication_failed` | Invalid client credentials |
| 401 | Unauthorized | `token_validation_failed` | Invalid or expired token |
| 401 | Unauthorized | `token_refresh_failed` | Invalid refresh token |
| 403 | Forbidden | `tenant_access_denied` | Tenant suspended/inactive |
| 403 | Forbidden | `insufficient_permissions` | Feature not available |
| 404 | Not Found | `tenant_not_found` | Tenant doesn't exist |
| 500 | Server Error | `tenant_context_missing` | Internal server error |

## Related Documentation

- [Multi-Tenant Auth Service Integration Guide](SAAS_CLIENT_GUIDE.md) - Main integration guide
- [Tenant Authentication Implementation Guide](TENANT_AUTHENTICATION_GUIDE.md) - Detailed implementation details
- [Two-Factor Authentication Guide](TWO_FACTOR_AUTHENTICATION_GUIDE.md) - 2FA implementation
- [Circuit Breaker Design Guide](CIRCUIT_BREAKER_DESIGN_GUIDE.md) - Fault tolerance patterns
- [Testing Documentation](TESTING.md) - Testing strategies and examples
- [Actuator Documentation](ACTUATOR.md) - Monitoring and health checks

This technical guide provides complete implementation details for tenant authentication flow with proper separation between tenant and user authentication phases. The examples and patterns shown here will help you build a robust and secure authentication system for your multi-tenant application. 