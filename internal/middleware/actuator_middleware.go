package middleware

import (
	"auth-service/internal/actuator"
	"time"

	"github.com/gin-gonic/gin"
)

// ActuatorMiddleware creates middleware for tracking request metrics
func ActuatorMiddleware(act *actuator.Actuator) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Track active request
		act.StartRequest(c.Request.Method, c.FullPath())

		// Process request
		c.Next()

		// Track request completion
		act.EndRequest(c.Request.Method, c.FullPath())

		// Record metrics
		duration := time.Since(start)
		status := c.Writer.Status()
		act.RecordRequest(c.Request.Method, c.FullPath(), status, duration)
	}
}

// HealthCheckMiddleware creates middleware for health check endpoints
func HealthCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add cache headers for health check endpoints
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}
