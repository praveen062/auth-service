package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	OAuth    OAuthConfig    `mapstructure:"oauth"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Cache    CacheConfig    `mapstructure:"cache"`
	Tenancy  TenancyConfig  `mapstructure:"tenancy"`
	OneTime  OneTimeConfig  `mapstructure:"one_time_auth"`
	Actuator ActuatorConfig `mapstructure:"actuator"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port           int           `mapstructure:"port"`
	GRPCPort       int           `mapstructure:"grpc_port"`
	Host           string        `mapstructure:"host"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout"`
	MaxHeaderBytes int           `mapstructure:"max_header_bytes"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Name            string        `mapstructure:"name"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// OAuthConfig holds OAuth configuration
type OAuthConfig struct {
	Google    GoogleOAuthConfig `mapstructure:"google"`
	Providers []OAuthProvider   `mapstructure:"providers"`
}

// GoogleOAuthConfig holds Google OAuth specific configuration
type GoogleOAuthConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"`
}

// OAuthProvider holds OAuth provider configuration
type OAuthProvider struct {
	Name            string `mapstructure:"name"`
	Enabled         bool   `mapstructure:"enabled"`
	ClientIDEnv     string `mapstructure:"client_id_env"`
	ClientSecretEnv string `mapstructure:"client_secret_env"`
	RedirectURL     string `mapstructure:"redirect_url"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret                 string `mapstructure:"secret"`
	ExpirationHours        int    `mapstructure:"expiration_hours"`
	RefreshExpirationHours int    `mapstructure:"refresh_expiration_hours"`
	Issuer                 string `mapstructure:"issuer"`
	Audience               string `mapstructure:"audience"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	BcryptCost             int      `mapstructure:"bcrypt_cost"`
	PasswordMinLength      int      `mapstructure:"password_min_length"`
	PasswordRequireUpper   bool     `mapstructure:"password_require_uppercase"`
	PasswordRequireLower   bool     `mapstructure:"password_require_lowercase"`
	PasswordRequireNumbers bool     `mapstructure:"password_require_numbers"`
	PasswordRequireSpecial bool     `mapstructure:"password_require_special"`
	RateLimitRequests      int      `mapstructure:"rate_limit_requests"`
	RateLimitWindow        string   `mapstructure:"rate_limit_window"`
	CORSAllowedOrigins     []string `mapstructure:"cors_allowed_origins"`
	CORSAllowedMethods     []string `mapstructure:"cors_allowed_methods"`
	CORSAllowedHeaders     []string `mapstructure:"cors_allowed_headers"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level             string `mapstructure:"level"`
	Format            string `mapstructure:"format"`
	Output            string `mapstructure:"output"`
	IncludeCaller     bool   `mapstructure:"include_caller"`
	IncludeStacktrace bool   `mapstructure:"include_stacktrace"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	TTL    CacheTTLConfig    `mapstructure:"ttl"`
	Prefix CachePrefixConfig `mapstructure:"prefix"`
}

// CacheTTLConfig holds cache TTL configuration
type CacheTTLConfig struct {
	UserSession  string `mapstructure:"user_session"`
	TenantConfig string `mapstructure:"tenant_config"`
	OAuthState   string `mapstructure:"oauth_state"`
	OneTimeToken string `mapstructure:"one_time_token"`
}

// CachePrefixConfig holds cache prefix configuration
type CachePrefixConfig struct {
	UserSession  string `mapstructure:"user_session"`
	TenantConfig string `mapstructure:"tenant_config"`
	OAuthState   string `mapstructure:"oauth_state"`
	OneTimeToken string `mapstructure:"one_time_token"`
}

// TenancyConfig holds multi-tenancy configuration
type TenancyConfig struct {
	DefaultTenantID   string `mapstructure:"default_tenant_id"`
	TenantHeader      string `mapstructure:"tenant_header"`
	TenantCookie      string `mapstructure:"tenant_cookie"`
	AutoCreateTenant  bool   `mapstructure:"auto_create_tenant"`
	MaxTenantsPerUser int    `mapstructure:"max_tenants_per_user"`
}

// OneTimeConfig holds one-time authentication configuration
type OneTimeConfig struct {
	TokenLength     int      `mapstructure:"token_length"`
	MaxUses         int      `mapstructure:"max_uses"`
	ExpirationHours int      `mapstructure:"expiration_hours"`
	AllowedURLs     []string `mapstructure:"allowed_urls"`
}

// ActuatorConfig holds actuator configuration
type ActuatorConfig struct {
	Enabled          bool                   `mapstructure:"enabled"`
	BasePath         string                 `mapstructure:"base_path"`
	Health           HealthConfig           `mapstructure:"health"`
	Metrics          MetricsConfig          `mapstructure:"metrics"`
	Endpoints        EndpointsConfig        `mapstructure:"endpoints"`
	ActuatorSecurity ActuatorSecurityConfig `mapstructure:"security"`
}

// HealthConfig holds health check configuration
type HealthConfig struct {
	Enabled                bool          `mapstructure:"enabled"`
	Timeout                time.Duration `mapstructure:"timeout"`
	MemoryThresholdPercent int           `mapstructure:"memory_threshold_percent"`
	GoroutineThreshold     int           `mapstructure:"goroutine_threshold"`
	DiskSpaceThresholdGB   int64         `mapstructure:"disk_space_threshold_gb"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	PrometheusEnabled bool `mapstructure:"prometheus_enabled"`
	RequestTracking   bool `mapstructure:"request_tracking"`
}

// EndpointsConfig holds endpoint configuration
type EndpointsConfig struct {
	Health      bool `mapstructure:"health"`
	Info        bool `mapstructure:"info"`
	Metrics     bool `mapstructure:"metrics"`
	Prometheus  bool `mapstructure:"prometheus"`
	Status      bool `mapstructure:"status"`
	Uptime      bool `mapstructure:"uptime"`
	ThreadDump  bool `mapstructure:"threaddump"`
	HeapDump    bool `mapstructure:"heapdump"`
	ConfigProps bool `mapstructure:"configprops"`
	Mappings    bool `mapstructure:"mappings"`
	Loggers     bool `mapstructure:"loggers"`
}

// ActuatorSecurityConfig holds actuator security configuration
type ActuatorSecurityConfig struct {
	HealthPublic                 bool     `mapstructure:"health_public"`
	MetricsPublic                bool     `mapstructure:"metrics_public"`
	SensitiveEndpointsRestricted bool     `mapstructure:"sensitive_endpoints_restricted"`
	AllowedIPs                   []string `mapstructure:"allowed_ips"`
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Read environment variables
	viper.AutomaticEnv()

	// Set default values
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Override with environment variables
	overrideWithEnvVars()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.grpc_port", 9090)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.max_header_bytes", 1048576)

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "auth_service")
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "password")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "5m")

	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 5)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")

	viper.SetDefault("jwt.expiration_hours", 24)
	viper.SetDefault("jwt.refresh_expiration_hours", 168)
	viper.SetDefault("jwt.issuer", "auth-service")
	viper.SetDefault("jwt.audience", "auth-service-users")

	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.password_min_length", 8)
	viper.SetDefault("security.password_require_uppercase", true)
	viper.SetDefault("security.password_require_lowercase", true)
	viper.SetDefault("security.password_require_numbers", true)
	viper.SetDefault("security.password_require_special", true)
	viper.SetDefault("security.rate_limit_requests", 100)
	viper.SetDefault("security.rate_limit_window", "1m")

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.include_caller", true)
	viper.SetDefault("logging.include_stacktrace", true)

	viper.SetDefault("tenancy.default_tenant_id", "default")
	viper.SetDefault("tenancy.tenant_header", "X-Tenant-ID")
	viper.SetDefault("tenancy.tenant_cookie", "tenant_id")
	viper.SetDefault("tenancy.auto_create_tenant", true)
	viper.SetDefault("tenancy.max_tenants_per_user", 10)

	viper.SetDefault("one_time_auth.token_length", 32)
	viper.SetDefault("one_time_auth.max_uses", 1)
	viper.SetDefault("one_time_auth.expiration_hours", 1)

	viper.SetDefault("actuator.enabled", false)
	viper.SetDefault("actuator.base_path", "/actuator")
	viper.SetDefault("actuator.health.enabled", true)
	viper.SetDefault("actuator.health.timeout", "5s")
	viper.SetDefault("actuator.health.memory_threshold_percent", 90)
	viper.SetDefault("actuator.health.goroutine_threshold", 1000)
	viper.SetDefault("actuator.health.disk_space_threshold_gb", 10)
	viper.SetDefault("actuator.metrics.enabled", true)
	viper.SetDefault("actuator.metrics.prometheus_enabled", true)
	viper.SetDefault("actuator.metrics.request_tracking", true)
	viper.SetDefault("actuator.endpoints.health", true)
	viper.SetDefault("actuator.endpoints.info", true)
	viper.SetDefault("actuator.endpoints.metrics", true)
	viper.SetDefault("actuator.endpoints.prometheus", true)
	viper.SetDefault("actuator.endpoints.status", true)
	viper.SetDefault("actuator.endpoints.uptime", true)
	viper.SetDefault("actuator.endpoints.threaddump", true)
	viper.SetDefault("actuator.endpoints.heapdump", true)
	viper.SetDefault("actuator.endpoints.configprops", true)
	viper.SetDefault("actuator.endpoints.mappings", true)
	viper.SetDefault("actuator.endpoints.loggers", true)
	viper.SetDefault("actuator.security.health_public", true)
	viper.SetDefault("actuator.security.metrics_public", true)
	viper.SetDefault("actuator.security.sensitive_endpoints_restricted", true)
	viper.SetDefault("actuator.security.allowed_ips", []string{})
}

// overrideWithEnvVars overrides configuration with environment variables
func overrideWithEnvVars() {
	// Server
	if serverPort := viper.GetInt("SERVER_PORT"); serverPort != 0 {
		viper.Set("server.port", serverPort)
	}
	if serverHost := viper.GetString("SERVER_HOST"); serverHost != "" {
		viper.Set("server.host", serverHost)
	}

	// Database
	if dbHost := viper.GetString("DB_HOST"); dbHost != "" {
		viper.Set("database.host", dbHost)
	}
	if dbPort := viper.GetInt("DB_PORT"); dbPort != 0 {
		viper.Set("database.port", dbPort)
	}
	if dbName := viper.GetString("DB_NAME"); dbName != "" {
		viper.Set("database.name", dbName)
	}
	if dbUser := viper.GetString("DB_USER"); dbUser != "" {
		viper.Set("database.user", dbUser)
	}
	if dbPassword := viper.GetString("DB_PASSWORD"); dbPassword != "" {
		viper.Set("database.password", dbPassword)
	}

	// Redis
	if redisHost := viper.GetString("REDIS_HOST"); redisHost != "" {
		viper.Set("redis.host", redisHost)
	}
	if redisPort := viper.GetInt("REDIS_PORT"); redisPort != 0 {
		viper.Set("redis.port", redisPort)
	}
	if redisPassword := viper.GetString("REDIS_PASSWORD"); redisPassword != "" {
		viper.Set("redis.password", redisPassword)
	}

	// JWT
	if jwtSecret := viper.GetString("JWT_SECRET"); jwtSecret != "" {
		viper.Set("jwt.secret", jwtSecret)
	}

	// OAuth
	if googleClientID := viper.GetString("GOOGLE_CLIENT_ID"); googleClientID != "" {
		viper.Set("oauth.google.client_id", googleClientID)
	}
	if googleClientSecret := viper.GetString("GOOGLE_CLIENT_SECRET"); googleClientSecret != "" {
		viper.Set("oauth.google.client_secret", googleClientSecret)
	}

	// Actuator
	if actuatorEnabled := viper.GetBool("ACTUATOR_ENABLED"); actuatorEnabled {
		viper.Set("actuator.enabled", true)
	}
	if actuatorBasePath := viper.GetString("ACTUATOR_BASE_PATH"); actuatorBasePath != "" {
		viper.Set("actuator.base_path", actuatorBasePath)
	}
	if actuatorHealthEnabled := viper.GetBool("ACTUATOR_HEALTH_ENABLED"); actuatorHealthEnabled {
		viper.Set("actuator.health.enabled", true)
	}
	if actuatorHealthTimeout := viper.GetDuration("ACTUATOR_HEALTH_TIMEOUT"); actuatorHealthTimeout != 0 {
		viper.Set("actuator.health.timeout", actuatorHealthTimeout)
	}
	if actuatorHealthMemoryThresholdPercent := viper.GetInt("ACTUATOR_HEALTH_MEMORY_THRESHOLD_PERCENT"); actuatorHealthMemoryThresholdPercent != 0 {
		viper.Set("actuator.health.memory_threshold_percent", actuatorHealthMemoryThresholdPercent)
	}
	if actuatorHealthGoroutineThreshold := viper.GetInt("ACTUATOR_HEALTH_GOROUTINE_THRESHOLD"); actuatorHealthGoroutineThreshold != 0 {
		viper.Set("actuator.health.goroutine_threshold", actuatorHealthGoroutineThreshold)
	}
	if actuatorHealthDiskSpaceThresholdGB := viper.GetInt64("ACTUATOR_HEALTH_DISK_SPACE_THRESHOLD_GB"); actuatorHealthDiskSpaceThresholdGB != 0 {
		viper.Set("actuator.health.disk_space_threshold_gb", actuatorHealthDiskSpaceThresholdGB)
	}
	if actuatorMetricsEnabled := viper.GetBool("ACTUATOR_METRICS_ENABLED"); actuatorMetricsEnabled {
		viper.Set("actuator.metrics.enabled", true)
	}
	if actuatorMetricsPrometheusEnabled := viper.GetBool("ACTUATOR_METRICS_PROMETHEUS_ENABLED"); actuatorMetricsPrometheusEnabled {
		viper.Set("actuator.metrics.prometheus_enabled", true)
	}
	if actuatorMetricsRequestTracking := viper.GetBool("ACTUATOR_METRICS_REQUEST_TRACKING"); actuatorMetricsRequestTracking {
		viper.Set("actuator.metrics.request_tracking", true)
	}
	if actuatorEndpointsHealth := viper.GetBool("ACTUATOR_ENDPOINTS_HEALTH"); actuatorEndpointsHealth {
		viper.Set("actuator.endpoints.health", true)
	}
	if actuatorEndpointsInfo := viper.GetBool("ACTUATOR_ENDPOINTS_INFO"); actuatorEndpointsInfo {
		viper.Set("actuator.endpoints.info", true)
	}
	if actuatorEndpointsMetrics := viper.GetBool("ACTUATOR_ENDPOINTS_METRICS"); actuatorEndpointsMetrics {
		viper.Set("actuator.endpoints.metrics", true)
	}
	if actuatorEndpointsPrometheus := viper.GetBool("ACTUATOR_ENDPOINTS_PROMETHEUS"); actuatorEndpointsPrometheus {
		viper.Set("actuator.endpoints.prometheus", true)
	}
	if actuatorEndpointsStatus := viper.GetBool("ACTUATOR_ENDPOINTS_STATUS"); actuatorEndpointsStatus {
		viper.Set("actuator.endpoints.status", true)
	}
	if actuatorEndpointsUptime := viper.GetBool("ACTUATOR_ENDPOINTS_UPTIME"); actuatorEndpointsUptime {
		viper.Set("actuator.endpoints.uptime", true)
	}
	if actuatorEndpointsThreadDump := viper.GetBool("ACTUATOR_ENDPOINTS_THREAD_DUMP"); actuatorEndpointsThreadDump {
		viper.Set("actuator.endpoints.threaddump", true)
	}
	if actuatorEndpointsHeapDump := viper.GetBool("ACTUATOR_ENDPOINTS_HEAP_DUMP"); actuatorEndpointsHeapDump {
		viper.Set("actuator.endpoints.heapdump", true)
	}
	if actuatorEndpointsConfigProps := viper.GetBool("ACTUATOR_ENDPOINTS_CONFIG_PROPS"); actuatorEndpointsConfigProps {
		viper.Set("actuator.endpoints.configprops", true)
	}
	if actuatorEndpointsMappings := viper.GetBool("ACTUATOR_ENDPOINTS_MAPPINGS"); actuatorEndpointsMappings {
		viper.Set("actuator.endpoints.mappings", true)
	}
	if actuatorEndpointsLoggers := viper.GetBool("ACTUATOR_ENDPOINTS_LOGGERS"); actuatorEndpointsLoggers {
		viper.Set("actuator.endpoints.loggers", true)
	}
	if actuatorSecurityHealthPublic := viper.GetBool("ACTUATOR_SECURITY_HEALTH_PUBLIC"); actuatorSecurityHealthPublic {
		viper.Set("actuator.security.health_public", true)
	}
	if actuatorSecurityMetricsPublic := viper.GetBool("ACTUATOR_SECURITY_METRICS_PUBLIC"); actuatorSecurityMetricsPublic {
		viper.Set("actuator.security.metrics_public", true)
	}
	if actuatorSecuritySensitiveEndpointsRestricted := viper.GetBool("ACTUATOR_SECURITY_SENSITIVE_ENDPOINTS_RESTRICTED"); actuatorSecuritySensitiveEndpointsRestricted {
		viper.Set("actuator.security.sensitive_endpoints_restricted", true)
	}
	if actuatorSecurityAllowedIPs := viper.GetStringSlice("ACTUATOR_SECURITY_ALLOWED_IPS"); len(actuatorSecurityAllowedIPs) > 0 {
		viper.Set("actuator.security.allowed_ips", actuatorSecurityAllowedIPs)
	}
}

// GetDSN returns the database connection string
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode)
}

// GetRedisAddr returns the Redis address
func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
