package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to isolate environment variables for tests
func isolateEnvVars(t *testing.T, testFunc func()) {
	// Store original environment variables
	originalVars := make(map[string]string)
	envVars := []string{
		"DB_HOST", "DB_PASSWORD", "JWT_SECRET", "SERVER_PORT", "DATABASE_HOST",
		"DB_PORT", "DB_NAME", "DB_USER", "REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD",
		"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			originalVars[envVar] = value
		}
	}

	// Set test environment variables
	os.Setenv("DB_HOST", "test-db-host")
	os.Setenv("DB_PASSWORD", "test-db-password")
	os.Setenv("JWT_SECRET", "test-jwt-secret")
	os.Setenv("SERVER_PORT", "8080")
	os.Setenv("DATABASE_HOST", "test-database-host")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_NAME", "test-auth-service")
	os.Setenv("DB_USER", "test-user")
	os.Setenv("REDIS_HOST", "test-redis-host")
	os.Setenv("REDIS_PORT", "6379")
	os.Setenv("REDIS_PASSWORD", "test-redis-password")
	os.Setenv("GOOGLE_CLIENT_ID", "test-google-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "test-google-client-secret")

	// Restore original values after test
	defer func() {
		// First, unset all test variables
		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}
		// Then restore original values
		for envVar, value := range originalVars {
			os.Setenv(envVar, value)
		}
	}()

	// Run the test
	testFunc()
}

func TestLoadConfig_Success(t *testing.T) {
	isolateEnvVars(t, func() {
		// Setup - create a temporary config file
		configContent := `
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "30s"
  write_timeout: "30s"

database:
  host: "localhost"
  port: 5432
  name: "test_db"
  user: "test_user"
  password: "test_password"

oauth:
  google:
    client_id: "test-client-id"
    client_secret: "test-client-secret"
    redirect_url: "http://localhost:8080/callback"
    scopes:
      - "email"
      - "profile"

jwt:
  secret: "test-secret"
  expiration_hours: 24
  refresh_expiration_hours: 168
  issuer: "test-issuer"
  audience: "test-audience"
`

		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Execute
		cfg, err := LoadConfig(tmpFile.Name())

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, cfg)

		// Check server config
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)

		// Check database config - environment variables should override config file values
		assert.Equal(t, "test-db-host", cfg.Database.Host) // From environment variable
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "test-auth-service", cfg.Database.Name)    // From environment variable
		assert.Equal(t, "test-user", cfg.Database.User)            // From environment variable
		assert.Equal(t, "test-db-password", cfg.Database.Password) // From environment variable

		// Check OAuth config - environment variables should override config file values
		assert.Equal(t, "test-google-client-id", cfg.OAuth.Google.ClientID)         // From environment variable
		assert.Equal(t, "test-google-client-secret", cfg.OAuth.Google.ClientSecret) // From environment variable
		assert.Equal(t, "http://localhost:8080/callback", cfg.OAuth.Google.RedirectURL)
		assert.Len(t, cfg.OAuth.Google.Scopes, 2)
		assert.Contains(t, cfg.OAuth.Google.Scopes, "email")
		assert.Contains(t, cfg.OAuth.Google.Scopes, "profile")

		// Check JWT config - environment variable should override config file value
		assert.Equal(t, "test-jwt-secret", cfg.JWT.Secret) // From environment variable
		assert.Equal(t, 24, cfg.JWT.ExpirationHours)
		assert.Equal(t, 168, cfg.JWT.RefreshExpirationHours)
		assert.Equal(t, "test-issuer", cfg.JWT.Issuer)
		assert.Equal(t, "test-audience", cfg.JWT.Audience)
	})
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	// Execute
	cfg, err := LoadConfig("nonexistent-config.yaml")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// Setup - create a temporary config file with invalid YAML
	configContent := `
server:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "30s"
  write_timeout: "30s"
  invalid_field: [invalid yaml
`

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(configContent)
	require.NoError(t, err)
	tmpFile.Close()

	// Execute
	cfg, err := LoadConfig(tmpFile.Name())

	// Assert
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoadConfig_WithEnvironmentVariables(t *testing.T) {
	isolateEnvVars(t, func() {
		// Setup - create a temporary config file
		configContent := `
server:
  port: 8080
  host: "0.0.0.0"

database:
  host: "localhost"
  port: 5432
  name: "test_db"
  user: "test_user"
  password: "test_password"
`

		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Execute
		cfg, err := LoadConfig(tmpFile.Name())

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, cfg)

		// Environment variables should override config file values
		assert.Equal(t, "test-db-host", cfg.Database.Host)
		assert.Equal(t, "test-db-password", cfg.Database.Password)
		assert.Equal(t, "test-jwt-secret", cfg.JWT.Secret)

		// Other values should remain from config file
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "test-auth-service", cfg.Database.Name) // From environment variable
		assert.Equal(t, "test-user", cfg.Database.User)         // From environment variable
	})
}

func TestLoadConfig_DefaultValues(t *testing.T) {
	isolateEnvVars(t, func() {
		// Setup - create a minimal config file
		configContent := `
server:
  port: 8080
  host: "0.0.0.0"
`

		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Execute
		cfg, err := LoadConfig(tmpFile.Name())

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, cfg)

		// Check default values are set
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, 9090, cfg.Server.GRPCPort)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, 30*time.Second, cfg.Server.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.Server.WriteTimeout)
		assert.Equal(t, 1048576, cfg.Server.MaxHeaderBytes)

		// Database defaults - environment variables should override defaults
		assert.Equal(t, "test-db-host", cfg.Database.Host) // From environment variable
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "test-auth-service", cfg.Database.Name)    // From environment variable
		assert.Equal(t, "test-user", cfg.Database.User)            // From environment variable
		assert.Equal(t, "test-db-password", cfg.Database.Password) // From environment variable
		assert.Equal(t, "disable", cfg.Database.SSLMode)
		assert.Equal(t, 25, cfg.Database.MaxOpenConns)
		assert.Equal(t, 5, cfg.Database.MaxIdleConns)
		assert.Equal(t, 5*time.Minute, cfg.Database.ConnMaxLifetime)

		// Redis defaults - environment variables should override defaults
		assert.Equal(t, "test-redis-host", cfg.Redis.Host) // From environment variable
		assert.Equal(t, 6379, cfg.Redis.Port)
		assert.Equal(t, "test-redis-password", cfg.Redis.Password) // From environment variable
		assert.Equal(t, 0, cfg.Redis.DB)
		assert.Equal(t, 10, cfg.Redis.PoolSize)
		assert.Equal(t, 5, cfg.Redis.MinIdleConns)
		assert.Equal(t, 5*time.Second, cfg.Redis.DialTimeout)
		assert.Equal(t, 3*time.Second, cfg.Redis.ReadTimeout)
		assert.Equal(t, 3*time.Second, cfg.Redis.WriteTimeout)

		// Security defaults
		assert.Equal(t, 12, cfg.Security.BcryptCost)
		assert.Equal(t, 8, cfg.Security.PasswordMinLength)
		assert.True(t, cfg.Security.PasswordRequireUpper)
		assert.True(t, cfg.Security.PasswordRequireLower)
		assert.True(t, cfg.Security.PasswordRequireNumbers)
		assert.True(t, cfg.Security.PasswordRequireSpecial)
		assert.Equal(t, 100, cfg.Security.RateLimitRequests)
		assert.Equal(t, "1m", cfg.Security.RateLimitWindow)

		// Logging defaults
		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "json", cfg.Logging.Format)
		assert.Equal(t, "stdout", cfg.Logging.Output)
		assert.True(t, cfg.Logging.IncludeCaller)
		assert.True(t, cfg.Logging.IncludeStacktrace)

		// Tenancy defaults
		assert.Equal(t, "default", cfg.Tenancy.DefaultTenantID)
		assert.Equal(t, "X-Tenant-ID", cfg.Tenancy.TenantHeader)
		assert.Equal(t, "tenant_id", cfg.Tenancy.TenantCookie)
		assert.True(t, cfg.Tenancy.AutoCreateTenant)
		assert.Equal(t, 10, cfg.Tenancy.MaxTenantsPerUser)

		// OneTime defaults
		assert.Equal(t, 32, cfg.OneTime.TokenLength)
		assert.Equal(t, 1, cfg.OneTime.MaxUses)
		assert.Equal(t, 1, cfg.OneTime.ExpirationHours)
	})
}

func TestDatabaseConfig_GetDSN(t *testing.T) {
	// Setup
	dbConfig := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "test_db",
		User:     "test_user",
		Password: "test_password",
		SSLMode:  "disable",
	}

	// Execute
	dsn := dbConfig.GetDSN()

	// Assert
	expectedDSN := "host=localhost port=5432 user=test_user password=test_password dbname=test_db sslmode=disable"
	assert.Equal(t, expectedDSN, dsn)
}

func TestDatabaseConfig_GetDSN_WithSSL(t *testing.T) {
	// Setup
	dbConfig := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "test_db",
		User:     "test_user",
		Password: "test_password",
		SSLMode:  "require",
	}

	// Execute
	dsn := dbConfig.GetDSN()

	// Assert
	expectedDSN := "host=localhost port=5432 user=test_user password=test_password dbname=test_db sslmode=require"
	assert.Equal(t, expectedDSN, dsn)
}

func TestRedisConfig_GetRedisAddr(t *testing.T) {
	// Setup
	redisConfig := RedisConfig{
		Host: "localhost",
		Port: 6379,
	}

	// Execute
	addr := redisConfig.GetRedisAddr()

	// Assert
	assert.Equal(t, "localhost:6379", addr)
}

func TestRedisConfig_GetRedisAddr_CustomHost(t *testing.T) {
	// Setup
	redisConfig := RedisConfig{
		Host: "redis.example.com",
		Port: 6380,
	}

	// Execute
	addr := redisConfig.GetRedisAddr()

	// Assert
	assert.Equal(t, "redis.example.com:6380", addr)
}

func TestConfig_Validation(t *testing.T) {
	isolateEnvVars(t, func() {
		// Setup - create a config with invalid values
		configContent := `
server:
  port: -1  # Invalid port
  host: ""

database:
  host: ""
  port: 0
  name: ""
  user: ""
  password: ""

oauth:
  google:
    client_id: ""
    client_secret: ""
    redirect_url: ""

jwt:
  secret: ""
  expiration_hours: 0
  refresh_expiration_hours: 0
`

		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Execute
		cfg, err := LoadConfig(tmpFile.Name())

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, cfg)

		// Environment variables should override empty values
		assert.Equal(t, 8080, cfg.Server.Port)             // From environment variable
		assert.Equal(t, "test-db-host", cfg.Database.Host) // From environment variable
		assert.Equal(t, "test-jwt-secret", cfg.JWT.Secret) // From environment variable
	})
}

func TestConfig_CompleteConfiguration(t *testing.T) {
	isolateEnvVars(t, func() {
		// Setup - create a complete config file
		configContent := `
server:
  port: 8080
  grpc_port: 9090
  host: "0.0.0.0"
  read_timeout: "30s"
  write_timeout: "30s"
  max_header_bytes: 1048576

database:
  host: "localhost"
  port: 5432
  name: "auth_service"
  user: "postgres"
  password: "password"
  sslmode: "disable"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
  pool_size: 10
  min_idle_conns: 5
  dial_timeout: "5s"
  read_timeout: "3s"
  write_timeout: "3s"

oauth:
  google:
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
    redirect_url: "http://localhost:8080/api/v1/oauth/google/callback"
    scopes:
      - "https://www.googleapis.com/auth/userinfo.email"
      - "https://www.googleapis.com/auth/userinfo.profile"
  
  providers:
    - name: "google"
      enabled: true
      client_id_env: "GOOGLE_CLIENT_ID"
      client_secret_env: "GOOGLE_CLIENT_SECRET"
      redirect_url: "http://localhost:8080/api/v1/oauth/google/callback"

jwt:
  secret: "your-super-secret-jwt-key-change-in-production"
  expiration_hours: 24
  refresh_expiration_hours: 168
  issuer: "auth-service"
  audience: "auth-service-users"

security:
  bcrypt_cost: 12
  password_min_length: 8
  password_require_uppercase: true
  password_require_lowercase: true
  password_require_numbers: true
  password_require_special: true
  rate_limit_requests: 100
  rate_limit_window: "1m"
  cors_allowed_origins:
    - "http://localhost:3000"
    - "http://localhost:8080"
  cors_allowed_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
    - "OPTIONS"
  cors_allowed_headers:
    - "Content-Type"
    - "Authorization"
    - "X-Requested-With"

logging:
  level: "info"
  format: "json"
  output: "stdout"
  include_caller: true
  include_stacktrace: true

cache:
  ttl:
    user_session: "24h"
    tenant_config: "1h"
    oauth_state: "10m"
    one_time_token: "1h"
  prefix:
    user_session: "session:"
    tenant_config: "tenant:"
    oauth_state: "oauth_state:"
    one_time_token: "one_time:"

tenancy:
  default_tenant_id: "default"
  tenant_header: "X-Tenant-ID"
  tenant_cookie: "tenant_id"
  auto_create_tenant: true
  max_tenants_per_user: 10

one_time_auth:
  token_length: 32
  max_uses: 1
  expiration_hours: 1
  allowed_urls:
    - "/api/v1/auth/verify"
    - "/api/v1/oauth/callback"
`

		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		// Execute
		cfg, err := LoadConfig(tmpFile.Name())

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, cfg)

		// Verify all sections are properly loaded
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, 9090, cfg.Server.GRPCPort)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)

		// Database - environment variables should override config file values
		assert.Equal(t, "test-db-host", cfg.Database.Host) // From environment variable
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "test-auth-service", cfg.Database.Name) // From environment variable

		// Redis - environment variables should override config file values
		assert.Equal(t, "test-redis-host", cfg.Redis.Host) // From environment variable
		assert.Equal(t, 6379, cfg.Redis.Port)

		// OAuth - environment variables should override config file values
		assert.Equal(t, "test-google-client-id", cfg.OAuth.Google.ClientID) // From environment variable
		assert.Len(t, cfg.OAuth.Google.Scopes, 2)
		assert.Len(t, cfg.OAuth.Providers, 1)
		assert.Equal(t, "google", cfg.OAuth.Providers[0].Name)
		assert.True(t, cfg.OAuth.Providers[0].Enabled)

		// JWT - environment variable should override config file value
		assert.Equal(t, "test-jwt-secret", cfg.JWT.Secret) // From environment variable
		assert.Equal(t, 24, cfg.JWT.ExpirationHours)
		assert.Equal(t, 168, cfg.JWT.RefreshExpirationHours)

		assert.Equal(t, 12, cfg.Security.BcryptCost)
		assert.Equal(t, 8, cfg.Security.PasswordMinLength)
		assert.Len(t, cfg.Security.CORSAllowedOrigins, 2)
		assert.Len(t, cfg.Security.CORSAllowedMethods, 5)
		assert.Len(t, cfg.Security.CORSAllowedHeaders, 3)

		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "json", cfg.Logging.Format)

		assert.Equal(t, "24h", cfg.Cache.TTL.UserSession)
		assert.Equal(t, "session:", cfg.Cache.Prefix.UserSession)

		assert.Equal(t, "default", cfg.Tenancy.DefaultTenantID)
		assert.Equal(t, "X-Tenant-ID", cfg.Tenancy.TenantHeader)
		assert.True(t, cfg.Tenancy.AutoCreateTenant)

		assert.Equal(t, 32, cfg.OneTime.TokenLength)
		assert.Equal(t, 1, cfg.OneTime.MaxUses)
		assert.Len(t, cfg.OneTime.AllowedURLs, 2)
	})
}
