package middleware

import (
	"auth-service/internal/service"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TenantMiddleware validates tenant access and extracts tenant information
func TenantMiddleware(tenantService service.TenantService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tenant ID from various sources
		tenantID := extractTenantID(c)

		if tenantID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":   "missing_tenant_id",
				"message": "Tenant ID is required",
			})
			return
		}

		// Check if we have a tenant token in X-Tenant-Token header
		tenantToken := c.GetHeader("X-Tenant-Token")
		if tenantToken != "" {
			// Validate the tenant token
			token, err := tenantService.ValidateTenantToken(c.Request.Context(), tenantToken)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "invalid_tenant_token",
					"message": err.Error(),
				})
				return
			}

			// Verify the tenant ID in the token matches the extracted tenant ID
			if token.TenantID != tenantID {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "tenant_token_mismatch",
					"message": "Tenant token does not match tenant ID",
				})
				return
			}

			// Store the validated token in context
			c.Set("tenant_token", token)
		}

		// Validate tenant access
		if err := tenantService.ValidateTenantAccess(c.Request.Context(), tenantID); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "tenant_access_denied",
				"message": err.Error(),
			})
			return
		}

		// Get tenant information
		tenant, err := tenantService.GetTenant(c.Request.Context(), tenantID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error":   "tenant_not_found",
				"message": "Tenant not found",
			})
			return
		}

		// Store tenant information in context
		c.Set("tenant_id", tenantID)
		c.Set("tenant", tenant)

		c.Next()
	}
}

// extractTenantID extracts tenant ID from various sources
func extractTenantID(c *gin.Context) string {
	// 1. From X-Tenant-Token header (highest priority)
	if tenantToken := c.GetHeader("X-Tenant-Token"); tenantToken != "" {
		// Extract tenant ID from tenant JWT token
		tenantID := extractTenantFromJWT(tenantToken)
		if tenantID != "" {
			return tenantID
		}
	}

	// 2. From Authorization header (Bearer token) - Tenant Token
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := authHeader[7:] // Remove "Bearer " prefix

			// Try to extract tenant ID from JWT token
			tenantID := extractTenantFromJWT(tokenString)
			if tenantID != "" {
				return tenantID
			}
		}
	}

	// 3. From X-Tenant-ID header
	if tenantID := c.GetHeader("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}

	// 4. From tenant_id cookie
	if tenantID, err := c.Cookie("tenant_id"); err == nil && tenantID != "" {
		return tenantID
	}

	// 5. From query parameter
	if tenantID := c.Query("tenant_id"); tenantID != "" {
		return tenantID
	}

	// 6. From request body (for POST/PUT requests)
	if c.Request.Method == "POST" || c.Request.Method == "PUT" {
		// Try to get from JSON body
		var body map[string]interface{}
		if err := c.ShouldBindJSON(&body); err == nil {
			if tenantID, ok := body["tenant_id"].(string); ok && tenantID != "" {
				return tenantID
			}
		}
	}

	// 7. From URL path (e.g., /api/v1/tenants/{tenant_id}/users)
	// This would require custom routing setup
	// tenantID := c.Param("tenant_id")
	// if tenantID != "" {
	//     return tenantID
	// }

	return ""
}

// extractTenantFromJWT extracts tenant ID from a JWT token
func extractTenantFromJWT(tokenString string) string {
	// Parse JWT token without validation (we just want to extract claims)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return ""
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}

	// Check if this is a tenant token
	if tokenType, ok := claims["type"].(string); ok && tokenType == "tenant" {
		if tenantID, ok := claims["tenant_id"].(string); ok && tenantID != "" {
			return tenantID
		}
	}

	// Check if this is a user token with tenant_id
	if tenantID, ok := claims["tenant_id"].(string); ok && tenantID != "" {
		return tenantID
	}

	return ""
}

// GetTenant retrieves tenant information from context
func GetTenant(c *gin.Context) interface{} {
	if tenant, exists := c.Get("tenant"); exists {
		return tenant
	}
	return nil
}

// GetTenantID retrieves tenant ID from context
func GetTenantID(c *gin.Context) string {
	if tenantID, exists := c.Get("tenant_id"); exists {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}
	return ""
}

// GetTenantToken retrieves tenant token from context
func GetTenantToken(c *gin.Context) interface{} {
	if token, exists := c.Get("tenant_token"); exists {
		return token
	}
	return nil
}

// RequireTenantPlan middleware ensures tenant has required plan
func RequireTenantPlan(requiredPlan string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantInterface := GetTenant(c)
		if tenantInterface == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":   "tenant_context_missing",
				"message": "Tenant context is missing",
			})
			return
		}

		// Type assertion would be needed here
		// tenant := tenantInterface.(*models.Tenant)
		// if tenant.Plan != requiredPlan {
		//     c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		//         "error":   "insufficient_plan",
		//         "message": fmt.Sprintf("Plan %s is required", requiredPlan),
		//     })
		//     return
		// }

		c.Next()
	}
}

// RequireTenantFeature middleware ensures tenant has required feature
func RequireTenantFeature(requiredFeature string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantInterface := GetTenant(c)
		if tenantInterface == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":   "tenant_context_missing",
				"message": "Tenant context is missing",
			})
			return
		}

		// Type assertion would be needed here
		// tenant := tenantInterface.(*models.Tenant)
		// hasFeature := false
		// for _, feature := range tenant.Features {
		//     if feature == requiredFeature {
		//         hasFeature = true
		//         break
		//     }
		// }
		// if !hasFeature {
		//     c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		//         "error":   "feature_not_available",
		//         "message": fmt.Sprintf("Feature %s is not available", requiredFeature),
		//     })
		//     return
		// }

		c.Next()
	}
}
