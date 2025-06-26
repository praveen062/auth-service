# Multi-Tenant Auth Service - Integration Guide

A comprehensive guide for integrating with the multi-tenant authentication service. This service provides isolated authentication environments for each tenant with configurable settings and features.

## Table of Contents

- [Quick Start](#quick-start)
- [Authentication Methods](#authentication-methods)
- [Tenant Configuration](#tenant-configuration)
- [Security Features](#security-features)
- [Frontend Integration](#frontend-integration)
- [Token Management](#token-management)
- [Monitoring](#monitoring)
- [Error Handling](#error-handling)
- [Security Best Practices](#security-best-practices)
- [Related Documentation](#related-documentation)

## Quick Start

### Creating a Tenant

First, you'll need to initialize a tenant for your application:

```bash
curl -X POST https://auth.yourdomain.com/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Your Application",
    "domain": "yourapp.com"
  }'
```

**Response:**
```json
{
  "id": "tenant-1234567890",
  "name": "Your Application",
  "domain": "yourapp.com",
  "status": "active",
  "features": ["oauth", "mfa", "audit"],
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Using Your Tenant ID

Include the tenant ID in all authentication requests:

```bash
# User Registration
curl -X POST https://auth.yourdomain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@yourapp.com",
    "password": "securepassword123",
    "tenant_id": "tenant-1234567890",
    "first_name": "John",
    "last_name": "Doe"
  }'

# User Login
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@yourapp.com",
    "password": "securepassword123",
    "tenant_id": "tenant-1234567890"
  }'
```

## Authentication Methods

### Email and Password Authentication

**User Registration:**
```bash
POST /api/v1/auth/register
{
  "email": "user@yourapp.com",
  "password": "securepassword123",
  "tenant_id": "your-tenant-id",
  "first_name": "John",
  "last_name": "Doe"
}
```

**User Login:**
```bash
POST /api/v1/auth/login
{
  "email": "user@yourapp.com",
  "password": "securepassword123",
  "tenant_id": "your-tenant-id"
}
```

**Successful Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "user-123",
    "email": "user@yourapp.com",
    "tenant_id": "your-tenant-id",
    "roles": [
      {
        "id": "role-1",
        "name": "user"
      }
    ]
  }
}
```

### OAuth Authentication

**Initiate Google OAuth:**
```bash
GET /api/v1/oauth/google/login?tenant_id=your-tenant-id
```

**Response:**
```json
{
  "auth_url": "https://accounts.google.com/oauth/authorize?...",
  "message": "Redirect to Google OAuth"
}
```

### Service-to-Service Authentication

For backend services communicating with each other:

```bash
POST /api/v1/oauth/token
{
  "grant_type": "client_credentials",
  "client_id": "your-service-client-id",
  "client_secret": "your-service-secret",
  "scope": "read:users write:users"
}
```

## Tenant Configuration

### Updating Tenant Settings

```bash
PUT /api/v1/tenants/your-tenant-id
{
  "name": "Updated Application Name",
  "status": "active"
}
```

### Getting Tenant Statistics

```bash
GET /api/v1/tenants/your-tenant-id/stats
```

**Response:**
```json
{
  "tenant_id": "your-tenant-id",
  "total_users": 150,
  "active_users": 120,
  "total_logins": 1250,
  "last_login_at": "2024-01-15T10:30:00Z",
  "storage_used": 52428800,
  "api_requests": 5000,
  "updated_at": "2024-01-15T10:30:00Z"
}
```

## Security Features

### Tenant Isolation
Each tenant's data is completely isolated from others. Users can only access resources within their tenant, and cross-tenant access is prevented by design.

### JWT Token Security
- Tokens include tenant information for validation
- Automatic token validation on protected endpoints
- Configurable token expiration times per tenant

### Rate Limiting
- Per-tenant rate limiting prevents abuse
- Configurable limits based on tenant settings
- Automatic throttling for excessive requests

### Audit Logging
- Complete audit trail of authentication events
- User activity tracking across the system
- Security event monitoring and alerting

## Frontend Integration

### JavaScript and React Example

Here's a complete authentication service implementation:

```javascript
class AuthService {
  constructor(tenantId, baseUrl) {
    this.tenantId = tenantId;
    this.baseUrl = baseUrl;
  }

  async login(email, password) {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password,
        tenant_id: this.tenantId
      })
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      return data;
    } else {
      throw new Error('Login failed');
    }
  }

  async register(userData) {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...userData,
        tenant_id: this.tenantId
      })
    });

    return response.json();
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    const response = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        refresh_token: refreshToken
      })
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      return data;
    } else {
      throw new Error('Token refresh failed');
    }
  }

  async makeAuthenticatedRequest(url, options = {}) {
    const token = localStorage.getItem('access_token');
    
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': this.tenantId
      }
    });

    if (response.status === 401) {
      // Token expired, try to refresh
      await this.refreshToken();
      return this.makeAuthenticatedRequest(url, options);
    }

    return response;
  }
}

// Usage
const authService = new AuthService('your-tenant-id', 'https://auth.yourdomain.com');

// Login
authService.login('user@yourapp.com', 'password123')
  .then(user => console.log('Logged in:', user))
  .catch(error => console.error('Login failed:', error));
```

### React Hook Example

```javascript
import { useState, useEffect } from 'react';

const useAuth = (tenantId) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const authService = new AuthService(tenantId, 'https://auth.yourdomain.com');

  const login = async (email, password) => {
    try {
      setLoading(true);
      const userData = await authService.login(email, password);
      setUser(userData.user);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setUser(null);
  };

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('access_token');
    if (token) {
      // Validate token and get user info
      // Implementation depends on your needs
    }
    setLoading(false);
  }, []);

  return { user, loading, error, login, logout };
};
```

## Token Management

### Automatic Token Refresh

Here's how to set up automatic token refresh for your application:

```javascript
// Interceptor for automatic token refresh
const setupTokenRefresh = (authService) => {
  const originalFetch = window.fetch;
  
  window.fetch = async (url, options = {}) => {
    // Add token to requests
    const token = localStorage.getItem('access_token');
    if (token) {
      options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': authService.tenantId
      };
    }

    let response = await originalFetch(url, options);

    // Handle 401 responses
    if (response.status === 401) {
      try {
        await authService.refreshToken();
        // Retry the original request
        const newToken = localStorage.getItem('access_token');
        options.headers = {
          ...options.headers,
          'Authorization': `Bearer ${newToken}`,
          'X-Tenant-ID': authService.tenantId
        };
        response = await originalFetch(url, options);
      } catch (error) {
        // Refresh failed, redirect to login
        window.location.href = '/login';
        return;
      }
    }

    return response;
  };
};
```

## Monitoring

### Usage Statistics

Get detailed statistics about your tenant's usage:

```bash
# Get tenant statistics
curl -H "Authorization: Bearer YOUR_TOKEN" \
     -H "X-Tenant-ID: your-tenant-id" \
     https://auth.yourdomain.com/api/v1/tenants/your-tenant-id/stats
```

### Health Checks

Monitor the service health:

```bash
# Check service health
curl https://auth.yourdomain.com/actuator/health
```

For more detailed monitoring information, see [ACTUATOR.md](ACTUATOR.md).

## Error Handling

### Common Error Responses

```json
{
  "error": "validation_error",
  "message": "Email is required"
}
```

```json
{
  "error": "tenant_access_denied",
  "message": "Tenant subscription has expired"
}
```

```json
{
  "error": "insufficient_permissions",
  "message": "Feature not available for current configuration"
}
```

## Security Best Practices

1. **Always use HTTPS** for all API calls in production
2. **Store tokens securely** using HttpOnly cookies for web applications
3. **Implement token refresh** logic to handle expired tokens gracefully
4. **Validate tokens** on your backend services
5. **Use environment variables** for sensitive configuration data
6. **Implement proper error handling** for all authentication flows
7. **Monitor usage** and set up alerts for suspicious activity
8. **Regular security audits** of your integration code

## Technical Considerations

### Performance
- Horizontal scaling is handled automatically by the service
- Database sharding by tenant ensures optimal performance
- CDN integration provides global performance optimization
- Automatic failover and disaster recovery mechanisms

### Integration Architecture
- RESTful API design following industry standards
- JWT-based authentication for stateless operation
- OAuth 2.0 support for third-party integrations
- OpenAPI documentation for easy integration

## Related Documentation

- [Tenant Authentication Guide](TENANT_AUTHENTICATION_GUIDE.md) - Detailed tenant authentication implementation
- [Tenant Authentication Examples](TENANT_AUTHENTICATION_EXAMPLES.md) - Complete flow examples
- [Two-Factor Authentication Guide](TWO_FACTOR_AUTHENTICATION_GUIDE.md) - 2FA implementation
- [Circuit Breaker Design Guide](CIRCUIT_BREAKER_DESIGN_GUIDE.md) - Fault tolerance patterns
- [Testing Documentation](TESTING.md) - Comprehensive testing guide
- [Actuator Documentation](ACTUATOR.md) - Monitoring and health checks

This integration guide provides the technical foundation you need to implement multi-tenant authentication in your application. If you have questions or need additional examples, please refer to the related documentation linked above. 