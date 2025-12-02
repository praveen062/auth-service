package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-service/internal/actuator"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestActuatorMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	appInfo := &actuator.AppInfo{
		Name:        "test-app",
		Version:     "1.0.0",
		Description: "Test application",
		Environment: "test",
	}

	act := actuator.NewActuator(appInfo)

	// Add actuator middleware
	router.Use(ActuatorMiddleware(act))

	// Add a test endpoint
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	// Test the endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// The middleware should have tracked the request
	// We can't easily test the internal metrics state, but we can verify
	// the request was processed without errors
}

func TestHealthCheckMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add health check middleware
	router.Use(HealthCheckMiddleware())

	// Add a test endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Test the endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that cache headers were set
	assert.Equal(t, "no-cache, no-store, must-revalidate", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "0", w.Header().Get("Expires"))
}
