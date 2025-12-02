package models

import (
	"time"
)

// Tenant represents a client organization using the auth service
type Tenant struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Domain       string         `json:"domain"`
	Status       string         `json:"status"` // active, suspended, inactive
	Plan         string         `json:"plan"`   // basic, pro, enterprise
	MaxUsers     int            `json:"max_users"`
	APIKey       string         `json:"api_key,omitempty"`       // For API authentication
	SecretKey    string         `json:"secret_key,omitempty"`    // For API authentication
	ClientID     string         `json:"client_id,omitempty"`     // OAuth client ID
	ClientSecret string         `json:"client_secret,omitempty"` // OAuth client secret
	Features     []string       `json:"features" db:"features"`
	Settings     TenantSettings `json:"settings"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// TenantSettings contains configuration for a tenant
type TenantSettings struct {
	AllowedOrigins   []string       `json:"allowed_origins"`
	CustomBranding   bool           `json:"custom_branding"`
	LogoURL          string         `json:"logo_url" db:"logo_url"`
	PrimaryColor     string         `json:"primary_color" db:"primary_color"`
	EnableOAuth      bool           `json:"enable_oauth"`
	EnableMFA        bool           `json:"enable_mfa"`
	PasswordPolicy   PasswordPolicy `json:"password_policy"`
	SessionTimeout   int            `json:"session_timeout"` // minutes
	MaxLoginAttempts int            `json:"max_login_attempts"`
	EnableAuditLog   bool           `json:"enable_audit_log"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireNumbers bool `json:"require_numbers"`
	RequireSpecial bool `json:"require_special"`
	MaxAge         int  `json:"max_age"` // days
}

// TenantStats contains usage statistics for a tenant
type TenantStats struct {
	TenantID    string    `json:"tenant_id"`
	TotalUsers  int       `json:"total_users"`
	ActiveUsers int       `json:"active_users"`
	TotalLogins int       `json:"total_logins"`
	LastLoginAt time.Time `json:"last_login_at"`
	StorageUsed int64     `json:"storage_used"` // bytes
	APIRequests int       `json:"api_requests"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TenantAuthRequest represents tenant authentication request
type TenantAuthRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	GrantType    string `json:"grant_type" binding:"required"` // client_credentials
}

// TenantAuthResponse represents tenant authentication response
type TenantAuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	TenantID     string `json:"tenant_id"`
	TenantName   string `json:"tenant_name"`
	Plan         string `json:"plan"`
}

// TenantToken represents a tenant authentication token
type TenantToken struct {
	TenantID  string    `json:"tenant_id"`
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
}

// TenantUserAuthRequest represents user authentication request within a tenant
type TenantUserAuthRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
}

// TenantUserAuthResponse represents user authentication response within a tenant
type TenantUserAuthResponse struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	TokenType    string     `json:"token_type"`
	ExpiresIn    int        `json:"expires_in"`
	User         TenantUser `json:"user"`
	Tenant       TenantInfo `json:"tenant"`
}

// TenantUser represents a user within a tenant
type TenantUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	TenantID string `json:"tenant_id"`
	Roles    []Role `json:"roles"`
}

// TenantInfo represents basic tenant information
type TenantInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Plan   string `json:"plan"`
}

// TenantPlan represents tenant plans
type TenantPlan struct {
	Name string `json:"name"`
	Plan string `json:"plan"`
}

// AdminUserRequest represents admin user creation request
type AdminUserRequest struct {
	Email    string `json:"email" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// CreateTenantRequest represents a tenant creation request
type CreateTenantRequest struct {
	Name      string           `json:"name" binding:"required"`
	Plan      string           `json:"plan" binding:"required"`
	Domain    string           `json:"domain"`
	Settings  TenantSettings   `json:"settings"`
	AdminUser AdminUserRequest `json:"admin_user"`
	OTPConfig *TenantOTPConfig `json:"otp_config,omitempty"`
}
