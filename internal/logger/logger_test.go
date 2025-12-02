package logger

import (
	"auth-service/internal/config"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	cfg := &config.LoggingConfig{
		Level:             "info",
		Format:            "json",
		Output:            "stdout",
		IncludeCaller:     true,
		IncludeStacktrace: true,
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestLogger_WithRequest(t *testing.T) {
	cfg := &config.LoggingConfig{
		Level:             "info",
		Format:            "json",
		Output:            "stdout",
		IncludeCaller:     true,
		IncludeStacktrace: true,
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "test-request-123")
	req.Header.Set("X-User-ID", "user-123")
	req.Header.Set("X-Tenant-ID", "tenant-123")

	reqLogger := logger.WithRequest(req)
	assert.NotNil(t, reqLogger)
	assert.Equal(t, "test-request-123", reqLogger.requestID)
	assert.Equal(t, "user-123", reqLogger.userID)
	assert.Equal(t, "tenant-123", reqLogger.tenantID)
	assert.Equal(t, "GET", reqLogger.method)
	assert.Equal(t, "/test", reqLogger.path)
}

func TestLogger_WithRequest_NoHeaders(t *testing.T) {
	cfg := &config.LoggingConfig{
		Level:             "info",
		Format:            "json",
		Output:            "stdout",
		IncludeCaller:     true,
		IncludeStacktrace: true,
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	reqLogger := logger.WithRequest(req)
	assert.NotNil(t, reqLogger)
	assert.NotEmpty(t, reqLogger.requestID) // Should generate a request ID
	assert.Equal(t, "POST", reqLogger.method)
	assert.Equal(t, "/api/v1/auth/login", reqLogger.path)
	assert.Equal(t, "192.168.1.1:12345", reqLogger.clientIP)
}

func TestRequestLogger_Methods(t *testing.T) {
	cfg := &config.LoggingConfig{
		Level:             "info",
		Format:            "json",
		Output:            "stdout",
		IncludeCaller:     true,
		IncludeStacktrace: true,
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	reqLogger := logger.WithRequest(req)

	// Test that these methods don't panic
	reqLogger.RequestStart()
	reqLogger.RequestEnd(200, 100, nil)
	reqLogger.AuthSuccess("user-123", "tenant-123", "password")
	reqLogger.AuthFailure("user-123", "tenant-123", "password", "invalid_credentials")
	reqLogger.OAuthFlow("google", "login_initiated", "tenant-123", nil)
	reqLogger.DatabaseOperation("SELECT", "users", "tenant-123", 50, nil)
	reqLogger.CacheOperation("GET", "user:123", "tenant-123", true, 10, nil)
	reqLogger.SecurityEvent("login_attempt", "user-123", "tenant-123", "Multiple failed attempts", "medium")
	reqLogger.BusinessEvent("user_login", "user-123", "tenant-123", map[string]interface{}{
		"login_method": "password",
		"success":      true,
	})
	reqLogger.Info("Test info message")
	reqLogger.Warn("Test warning message")
	reqLogger.Error("Test error message")
	reqLogger.Debug("Test debug message")
}
