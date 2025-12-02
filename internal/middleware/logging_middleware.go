package middleware

import (
	"auth-service/internal/logger"
	"auth-service/internal/tracing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LoggingMiddleware creates middleware for request-level logging
func LoggingMiddleware(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Create request-specific logger
		reqLogger := log.WithRequest(c.Request)

		// Log request start
		reqLogger.RequestStart()

		// Add logger to context for use in handlers
		c.Set("logger", reqLogger)

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Get response status
		status := c.Writer.Status()

		// Check for errors
		var err error
		if len(c.Errors) > 0 {
			err = c.Errors.Last().Err
		}

		// Add tracing headers to response
		traceCtx := &tracing.TracingContext{
			TraceID:      reqLogger.GetTraceID(),
			SpanID:       reqLogger.GetSpanID(),
			ParentSpanID: "", // This would be set if we had parent span info
		}
		tracing.AddTracingHeaders(c.Writer, traceCtx)

		// Log request end
		reqLogger.RequestEnd(status, duration, err)

		// Log additional request details for debugging
		if status >= 400 {
			reqLogger.Warn("Request resulted in error status",
				zap.String("user_agent", c.Request.UserAgent()),
				zap.String("referer", c.Request.Referer()),
				zap.Int64("content_length", c.Request.ContentLength),
			)
		}
	}
}

// GetLogger retrieves the request logger from context
func GetLogger(c *gin.Context) interface{} {
	if logger, exists := c.Get("logger"); exists {
		return logger
	}
	return nil
}

// SetUserContext adds user information to the request context for logging
func SetUserContext(c *gin.Context, userID, tenantID string) {
	// Note: This would need to be implemented in the logger package
	// For now, we'll just set the values in the request headers
	c.Request.Header.Set("X-User-ID", userID)
	c.Request.Header.Set("X-Tenant-ID", tenantID)
}
