# Tenant Authentication Implementation Guide

A comprehensive technical guide explaining how tenant authentication works in the multi-tenant auth service. This document covers the complete validation flow, response codes, and error scenarios to help developers integrate successfully.

## Table of Contents

- [Overview](#overview)
- [Authentication Flow](#authentication-flow)
- [HTTP Response Codes](#http-response-codes)
- [Tenant Validation](#tenant-validation)
- [Integration Examples](#integration-examples)
- [Middleware Implementation](#middleware-implementation)
- [Debugging and Troubleshooting](#debugging-and-troubleshooting)
- [Implementation Best Practices](#implementation-best-practices)
- [Monitoring and Metrics](#monitoring-and-metrics)
- [Related Documentation](#related-documentation)

## Overview

Tenant authentication is the foundation of our multi-tenant system. It ensures that every request is properly scoped to a specific tenant and that users can only access resources within their tenant boundary. This guide will walk you through the technical implementation details.

## Authentication Flow

### Step 1: Tenant ID Extraction

The middleware extracts tenant ID from multiple sources in priority order:

1. **Authorization Header** - Bearer Token with tenant claims
2. **X-Tenant-ID Header** - Direct tenant ID header
3. **tenant_id Cookie** - Cookie-based tenant identification
4. **Query Parameter** - URL query parameter `?tenant_id=...`
5. **Request Body** - For POST/PUT requests
6. **URL Path** - Configurable route parameters

Here's how the extraction works in practice:

```go
// Extraction implementation example
func extractTenantID(c *gin.Context) string {
    // 1. Check Authorization header for tenant token
    if token := extractBearerToken(c); token != "" {
        if claims, err := validateJWT(token); err == nil {
            if tenantID, exists := claims["tenant_id"]; exists {
                return tenantID.(string)
            }
        }
    }
    
    // 2. Check X-Tenant-ID header
    if tenantID := c.GetHeader("X-Tenant-ID"); tenantID != "" {
        return tenantID
    }
    
    // 3. Check cookie
    if cookie, err := c.Cookie("tenant_id"); err == nil {
        return cookie
    }
    
    // 4. Check query parameter
    if tenantID := c.Query("tenant_id"); tenantID != "" {
        return tenantID
    }
    
    // 5. Check request body
    var body map[string]interface{}
    if err := c.ShouldBindJSON(&body); err == nil {
        if tenantID, exists := body["tenant_id"]; exists {
            return tenantID.(string)
        }
    }
    
    return ""
}
```

### Step 2: Tenant Validation

Once we have the tenant ID, the system validates it through several checks:

1. **Tenant Existence** - Database lookup to verify the tenant exists
2. **Tenant Status** - Active/suspended/inactive status check
3. **Subscription Status** - Expiration and feature limits validation
4. **Feature Access** - Available features validation

```go
// Validation implementation
func validateTenant(tenantID string) (*Tenant, error) {
    tenant, err := tenantService.GetTenant(tenantID)
    if err != nil {
        return nil, errors.New("tenant_not_found")
    }
    
    if tenant.Status != "active" {
        return nil, fmt.Errorf("tenant is %s", tenant.Status)
    }
    
    if tenant.ExpiresAt != nil && time.Now().After(*tenant.ExpiresAt) {
        return nil, errors.New("tenant subscription has expired")
    }
    
    return tenant, nil
}
```

### Step 3: Context Injection

When validation passes, tenant information is stored in the request context for use by downstream handlers:

```go
func injectTenantContext(c *gin.Context, tenant *Tenant) {
    c.Set("tenant", tenant)
    c.Set("tenant_id", tenant.ID)
    c.Set("tenant_features", tenant.Features)
}
```

## HTTP Response Codes

Understanding the response codes helps you handle different scenarios appropriately.

### 400 Bad Request - Invalid Input

This occurs when the tenant ID is missing or malformed:

```json
{
  "error": "missing_tenant_id",
  "message": "Tenant ID is required"
}
```

**Common scenarios:**
- No tenant ID provided in any source
- Empty tenant ID value
- Malformed tenant ID format

### 401 Unauthorized - Authentication Issues

Authentication problems with tokens:

```json
{
  "error": "invalid_token",
  "message": "JWT token is invalid or expired"
}
```

**Common scenarios:**
- Invalid JWT signature
- Expired tenant token
- Malformed authorization header

### 403 Forbidden - Access Denied

Access is denied due to tenant status issues:

```json
{
  "error": "tenant_access_denied",
  "message": "Tenant is suspended"
}
```

**Possible states:**
- `"tenant is suspended"`
- `"tenant is inactive"`
- `"tenant subscription has expired"`
- `"feature not available"`

### 404 Not Found - Missing Resource

The tenant doesn't exist in the system:

```json
{
  "error": "tenant_not_found",
  "message": "Tenant not found"
}
```

### 500 Internal Server Error - System Issues

Internal system problems:

```json
{
  "error": "tenant_context_missing",
  "message": "Tenant context is missing from request"
}
```

## Tenant Validation

### Status Validation Logic

Here's how tenant status validation works:

```go
const (
    TenantStatusActive    = "active"
    TenantStatusSuspended = "suspended"
    TenantStatusInactive  = "inactive"
)

func validateTenantStatus(tenant *Tenant) error {
    switch tenant.Status {
    case TenantStatusActive:
        return nil
    case TenantStatusSuspended:
        return &ValidationError{
            Code:    "tenant_access_denied",
            Message: "tenant is suspended",
            Status:  http.StatusForbidden,
        }
    case TenantStatusInactive:
        return &ValidationError{
            Code:    "tenant_access_denied", 
            Message: "tenant is inactive",
            Status:  http.StatusForbidden,
        }
    default:
        return &ValidationError{
            Code:    "invalid_tenant_status",
            Message: fmt.Sprintf("unknown tenant status: %s", tenant.Status),
            Status:  http.StatusInternalServerError,
        }
    }
}
```

### Subscription Validation

Checking if the tenant's subscription is still valid:

```go
func validateSubscription(tenant *Tenant) error {
    if tenant.ExpiresAt != nil && time.Now().After(*tenant.ExpiresAt) {
        return &ValidationError{
            Code:    "tenant_access_denied",
            Message: "tenant subscription has expired",
            Status:  http.StatusForbidden,
        }
    }
    return nil
}
```

### Feature Access Validation

Ensuring the tenant has access to specific features:

```go
func validateFeatureAccess(tenant *Tenant, requiredFeature string) error {
    for _, feature := range tenant.Features {
        if feature == requiredFeature {
            return nil
        }
    }
    
    return &ValidationError{
        Code:    "feature_not_available",
        Message: fmt.Sprintf("feature %s is not available", requiredFeature),
        Status:  http.StatusForbidden,
    }
}
```

## Integration Examples

### Successful Authentication Flow

**Request with Header:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "X-Tenant-ID: tenant-1234567890" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "user-123",
    "email": "user@example.com",
    "tenant_id": "tenant-1234567890",
    "roles": [{"id": "role-1", "name": "user"}]
  }
}
```

### Missing Tenant ID

**Request:**
```bash
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Response (400 Bad Request):**
```json
{
  "error": "missing_tenant_id",
  "message": "Tenant ID is required"
}
```

### Suspended Tenant

**Response (403 Forbidden):**
```json
{
  "error": "tenant_access_denied",
  "message": "Tenant is suspended"
}
```

### Feature Access Denied

**Response (403 Forbidden):**
```json
{
  "error": "feature_not_available",
  "message": "Feature oauth is not available"
}
```

## Middleware Implementation

### Basic Tenant Middleware

Here's how to implement the core tenant middleware:

```go
func TenantMiddleware(tenantService TenantService) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := extractTenantID(c)
        if tenantID == "" {
            c.JSON(http.StatusBadRequest, gin.H{
                "error":   "missing_tenant_id",
                "message": "Tenant ID is required",
            })
            c.Abort()
            return
        }

        tenant, err := validateTenant(tenantID)
        if err != nil {
            handleValidationError(c, err)
            c.Abort()
            return
        }

        injectTenantContext(c, tenant)
        c.Next()
    }
}
```

### Feature-Specific Middleware

For endpoints that require specific features:

```go
func RequireFeature(feature string) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenant, exists := c.Get("tenant")
        if !exists {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error":   "tenant_context_missing",
                "message": "Tenant context is missing",
            })
            c.Abort()
            return
        }

        if err := validateFeatureAccess(tenant.(*Tenant), feature); err != nil {
            handleValidationError(c, err)
            c.Abort()
            return
        }

        c.Next()
    }
}
```

### Route Configuration

Here's how to apply the middleware to your routes:

```go
// Routes requiring tenant authentication
router.Use(TenantMiddleware(tenantService))
{
    router.POST("/auth/login", authHandler.Login)
    router.POST("/auth/register", authHandler.Register)
    
    // Routes requiring specific features
    oauthGroup := router.Group("/oauth")
    oauthGroup.Use(RequireFeature("oauth"))
    {
        oauthGroup.GET("/google/login", oauthHandler.GoogleLogin)
        oauthGroup.GET("/google/callback", oauthHandler.GoogleCallback)
    }
}
```

## Debugging and Troubleshooting

### Check Tenant Status

Verify a tenant's current status:

```bash
curl -X GET https://auth.yourdomain.com/api/v1/tenants/your-tenant-id \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Validate Token

Test token validation:

```bash
curl -X POST https://auth.yourdomain.com/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "your-jwt-token"}'
```

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| `missing_tenant_id` | No tenant ID provided | Add `X-Tenant-ID` header or include in request body |
| `tenant_not_found` | Invalid tenant ID | Verify tenant exists in system |
| `tenant is suspended` | Tenant deactivated | Check tenant status and reactivate if needed |
| `feature_not_available` | Feature not configured | Enable feature in tenant configuration |

## Implementation Best Practices

### Consistent Tenant ID Handling

Frontend implementation example:

```javascript
// Frontend implementation
const apiClient = {
  tenantId: 'your-tenant-id',
  
  async request(endpoint, options = {}) {
    return fetch(endpoint, {
      ...options,
      headers: {
        'X-Tenant-ID': this.tenantId,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
  }
};
```

### Error Handling

Proper error handling in your application:

```javascript
async function handleApiCall(apiCall) {
  try {
    const response = await apiCall();
    return response.json();
  } catch (error) {
    if (error.status === 403 && error.error === 'tenant_access_denied') {
      // Handle tenant access issues
      redirectToTenantErrorPage(error.message);
    } else if (error.status === 400 && error.error === 'missing_tenant_id') {
      // Handle missing tenant ID
      ensureTenantIdPresent();
    }
    throw error;
  }
}
```

### Context Management

Helper functions for accessing tenant context:

```go
// Helper functions for accessing tenant context
func GetTenantFromContext(c *gin.Context) (*Tenant, error) {
    tenant, exists := c.Get("tenant")
    if !exists {
        return nil, errors.New("tenant context missing")
    }
    return tenant.(*Tenant), nil
}

func GetTenantIDFromContext(c *gin.Context) (string, error) {
    tenantID, exists := c.Get("tenant_id")
    if !exists {
        return "", errors.New("tenant_id context missing")
    }
    return tenantID.(string), nil
}
```

## Monitoring and Metrics

### Tenant Usage Metrics

The system tracks several important metrics:

- Authentication requests per tenant
- Failed authentication attempts
- Feature usage by tenant
- API request patterns
- Token validation performance

### Health Checks

Monitor tenant authentication health:

```bash
# Check tenant authentication health
curl -X GET https://auth.yourdomain.com/actuator/health/tenant
```

For detailed monitoring information, see [ACTUATOR.md](ACTUATOR.md).

## Related Documentation

- [Multi-Tenant Auth Service Integration Guide](SAAS_CLIENT_GUIDE.md) - Main integration guide
- [Tenant Authentication Examples](TENANT_AUTHENTICATION_EXAMPLES.md) - Complete flow examples
- [Two-Factor Authentication Guide](TWO_FACTOR_AUTHENTICATION_GUIDE.md) - 2FA implementation
- [Circuit Breaker Design Guide](CIRCUIT_BREAKER_DESIGN_GUIDE.md) - Fault tolerance patterns
- [Testing Documentation](TESTING.md) - Testing strategies and examples
- [Actuator Documentation](ACTUATOR.md) - Monitoring and health checks

This implementation guide provides the technical foundation for robust tenant authentication with proper validation, error handling, and debugging capabilities. The patterns and examples shown here will help you build a secure and maintainable multi-tenant application. 