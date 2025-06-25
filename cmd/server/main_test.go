package main

import (
	"auth-service/internal/config"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:           8080,
			GRPCPort:       9090,
			Host:           "0.0.0.0",
			ReadTimeout:    30,
			WriteTimeout:   30,
			MaxHeaderBytes: 1048576,
		},
		Database: config.DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			Name:            "test_db",
			User:            "test_user",
			Password:        "test_password",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 300,
		},
		Redis: config.RedisConfig{
			Host:         "localhost",
			Port:         6379,
			Password:     "",
			DB:           0,
			PoolSize:     10,
			MinIdleConns: 5,
			DialTimeout:  5,
			ReadTimeout:  3,
			WriteTimeout: 3,
		},
		OAuth: config.OAuthConfig{
			Google: config.GoogleOAuthConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/api/v1/oauth/google/callback",
				Scopes: []string{
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				},
			},
		},
		JWT: config.JWTConfig{
			Secret:                 "test-secret",
			ExpirationHours:        24,
			RefreshExpirationHours: 168,
			Issuer:                 "test-issuer",
			Audience:               "test-audience",
		},
		Security: config.SecurityConfig{
			BcryptCost:             12,
			PasswordMinLength:      8,
			PasswordRequireUpper:   true,
			PasswordRequireLower:   true,
			PasswordRequireNumbers: true,
			PasswordRequireSpecial: true,
			RateLimitRequests:      100,
			RateLimitWindow:        "1m",
			CORSAllowedOrigins:     []string{"http://localhost:3000"},
			CORSAllowedMethods:     []string{"GET", "POST", "PUT", "DELETE"},
			CORSAllowedHeaders:     []string{"Content-Type", "Authorization"},
		},
		Logging: config.LoggingConfig{
			Level:             "info",
			Format:            "json",
			Output:            "stdout",
			IncludeCaller:     true,
			IncludeStacktrace: true,
		},
		Cache: config.CacheConfig{
			TTL: config.CacheTTLConfig{
				UserSession:  "24h",
				TenantConfig: "1h",
				OAuthState:   "10m",
				OneTimeToken: "1h",
			},
			Prefix: config.CachePrefixConfig{
				UserSession:  "session:",
				TenantConfig: "tenant:",
				OAuthState:   "oauth_state:",
				OneTimeToken: "one_time:",
			},
		},
		Tenancy: config.TenancyConfig{
			DefaultTenantID:   "default",
			TenantHeader:      "X-Tenant-ID",
			TenantCookie:      "tenant_id",
			AutoCreateTenant:  true,
			MaxTenantsPerUser: 10,
		},
		OneTime: config.OneTimeConfig{
			TokenLength:     32,
			MaxUses:         1,
			ExpirationHours: 1,
			AllowedURLs: []string{
				"/api/v1/auth/verify",
				"/api/v1/oauth/callback",
			},
		},
	}
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestMain_LoadConfig_Success(t *testing.T) {
	// Setup - create a temporary config file
	configContent := `
server:
  port: 8080
  host: "0.0.0.0"

database:
  host: "localhost"
  port: 5432
  name: "test_db"

oauth:
  google:
    client_id: "test-client-id"
    client_secret: "test-client-secret"
    redirect_url: "http://localhost:8080/callback"

jwt:
  secret: "test-secret"
  expiration_hours: 24
`

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(configContent)
	require.NoError(t, err)
	tmpFile.Close()

	// Execute
	cfg, err := config.LoadConfig(tmpFile.Name())

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, "test-db-host", cfg.Database.Host)
	assert.Equal(t, "test-google-client-id", cfg.OAuth.Google.ClientID)
	assert.Equal(t, "test-jwt-secret", cfg.JWT.Secret)
}

func TestMain_LoadConfig_FileNotFound(t *testing.T) {
	// Execute
	cfg, err := config.LoadConfig("nonexistent-config.yaml")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestMain_IPAllowlistMiddleware_AllowedIP(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request from allowed IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["message"])
}

func TestMain_IPAllowlistMiddleware_BlockedIP(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request from blocked IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "forbidden: internal access only", response["error"])
}

func TestMain_IPAllowlistMiddleware_IPv6Allowed(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request from IPv6 localhost
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[::1]:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["message"])
}

func TestMain_IPAllowlistMiddleware_EmptyAllowedIPs(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request from any IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "forbidden: internal access only", response["error"])
}

func TestMain_IPAllowlistMiddleware_ProxyHeaders(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request with X-Forwarded-For header
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["message"])
}

func TestMain_IPAllowlistMiddleware_RealIPHeader(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request with X-Real-IP header
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-IP", "127.0.0.1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["message"])
}

func TestMain_IPAllowlistMiddleware_MultipleForwardedIPs(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request with multiple X-Forwarded-For IPs
	// The first IP in X-Forwarded-For is 192.168.1.100, which is not allowed
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 127.0.0.1, 10.0.0.1")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert - should be forbidden because the first IP (192.168.1.100) is not allowed
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "forbidden: internal access only", response["error"])
}

func TestMain_IPAllowlistMiddleware_InvalidIP(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"127.0.0.1", "::1"}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request with invalid IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "invalid-ip:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "forbidden: internal access only", response["error"])
}

func TestMain_IPAllowlistMiddleware_SubnetMatching(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"192.168.1.", "10.0.0."}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request from allowed subnet
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["message"])
}

func TestMain_IPAllowlistMiddleware_SubnetBlocked(t *testing.T) {
	// Setup
	router := setupTestRouter()
	allowedIPs := []string{"192.168.1.", "10.0.0."}

	router.Use(ipAllowlistMiddleware(allowedIPs))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute - request from blocked subnet
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "172.16.1.100:12345"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "forbidden: internal access only", response["error"])
}

func TestMain_ConfigurationValidation(t *testing.T) {
	// Test that the configuration structure is properly defined
	cfg := setupTestConfig()

	// Assert all required fields are present
	assert.NotEmpty(t, cfg.Server.Host)
	assert.Greater(t, cfg.Server.Port, 0)
	assert.NotEmpty(t, cfg.Database.Host)
	assert.Greater(t, cfg.Database.Port, 0)
	assert.NotEmpty(t, cfg.Database.Name)
	assert.NotEmpty(t, cfg.Database.User)
	assert.NotEmpty(t, cfg.JWT.Secret)
	assert.NotEmpty(t, cfg.OAuth.Google.ClientID)
	assert.NotEmpty(t, cfg.OAuth.Google.ClientSecret)
	assert.NotEmpty(t, cfg.OAuth.Google.RedirectURL)
	assert.Len(t, cfg.OAuth.Google.Scopes, 2)
	assert.Greater(t, cfg.Security.BcryptCost, 0)
	assert.Greater(t, cfg.Security.PasswordMinLength, 0)
	assert.Len(t, cfg.Security.CORSAllowedOrigins, 1)
	assert.Len(t, cfg.Security.CORSAllowedMethods, 4)
	assert.Len(t, cfg.Security.CORSAllowedHeaders, 2)
	assert.NotEmpty(t, cfg.Logging.Level)
	assert.NotEmpty(t, cfg.Logging.Format)
	assert.NotEmpty(t, cfg.Cache.TTL.UserSession)
	assert.NotEmpty(t, cfg.Cache.Prefix.UserSession)
	assert.NotEmpty(t, cfg.Tenancy.DefaultTenantID)
	assert.NotEmpty(t, cfg.Tenancy.TenantHeader)
	assert.Greater(t, cfg.OneTime.TokenLength, 0)
	assert.Greater(t, cfg.OneTime.MaxUses, 0)
	assert.Greater(t, cfg.OneTime.ExpirationHours, 0)
	assert.Len(t, cfg.OneTime.AllowedURLs, 2)
}

func TestMain_DatabaseDSN_Generation(t *testing.T) {
	// Test database DSN generation
	cfg := setupTestConfig()

	dsn := cfg.Database.GetDSN()
	expectedDSN := "host=localhost port=5432 user=test_user password=test_password dbname=test_db sslmode=disable"

	assert.Equal(t, expectedDSN, dsn)
}

func TestMain_RedisAddr_Generation(t *testing.T) {
	// Test Redis address generation
	cfg := setupTestConfig()

	addr := cfg.Redis.GetRedisAddr()
	expectedAddr := "localhost:6379"

	assert.Equal(t, expectedAddr, addr)
}

func TestMain_EnvironmentVariableOverride(t *testing.T) {
	// Setup environment variables using the correct names from overrideWithEnvVars
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("DB_HOST", "env-db-host")
	os.Setenv("JWT_SECRET", "env-jwt-secret")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("JWT_SECRET")
	}()

	// Create a minimal config file
	configContent := `
jwt:
  secret: "file-secret"
`

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(configContent)
	require.NoError(t, err)
	tmpFile.Close()

	// Execute
	cfg, err := config.LoadConfig(tmpFile.Name())

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	// Environment variables should override config file values
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "env-db-host", cfg.Database.Host)
	assert.Equal(t, "env-jwt-secret", cfg.JWT.Secret)
}
