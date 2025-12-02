package middleware

import (
	"auth-service/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RBACMiddleware returns a Gin middleware that checks for required permission
func RBACMiddleware(rbac service.RBACService, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		tenantID := c.GetString("tenant_id")
		if userID == "" || tenantID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user or tenant context"})
			return
		}
		hasPerm, err := rbac.UserHasPermission(c.Request.Context(), userID, permission, tenantID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "permission check failed"})
			return
		}
		if !hasPerm {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// For gRPC, similar interceptor logic would be used.
