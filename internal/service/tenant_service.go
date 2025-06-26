package service

import (
	"auth-service/internal/models"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TenantService defines the interface for tenant operations
type TenantService interface {
	CreateTenant(ctx context.Context, tenant *models.Tenant) error
	GetTenant(ctx context.Context, tenantID string) (*models.Tenant, error)
	GetTenantByClientID(ctx context.Context, clientID string) (*models.Tenant, error)
	UpdateTenant(ctx context.Context, tenant *models.Tenant) error
	DeleteTenant(ctx context.Context, tenantID string) error
	ListTenants(ctx context.Context, limit, offset int) ([]*models.Tenant, error)
	GetTenantStats(ctx context.Context, tenantID string) (*models.TenantStats, error)
	ValidateTenantAccess(ctx context.Context, tenantID string) error
	UpdateTenantStats(ctx context.Context, stats *models.TenantStats) error

	// Tenant Authentication
	AuthenticateTenant(ctx context.Context, req *models.TenantAuthRequest) (*models.TenantAuthResponse, error)
	ValidateTenantToken(ctx context.Context, token string) (*models.TenantToken, error)
	RefreshTenantToken(ctx context.Context, refreshToken string) (*models.TenantAuthResponse, error)
	RevokeTenantToken(ctx context.Context, token string) error
}

// tenantService implements TenantService
type tenantService struct {
	// TODO: Add database repository
	// repo repository.TenantRepository
}

// NewTenantService creates a new tenant service
func NewTenantService() TenantService {
	return &tenantService{}
}

// CreateTenant creates a new tenant (client organization)
func (s *tenantService) CreateTenant(ctx context.Context, tenant *models.Tenant) error {
	// Validate tenant data
	if tenant.Name == "" {
		return errors.New("tenant name is required")
	}
	if tenant.Domain == "" {
		return errors.New("tenant domain is required")
	}

	// Set default values
	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now
	tenant.Status = "active"

	// Set default settings based on plan
	s.setDefaultSettings(tenant)

	// TODO: Save to database
	// return s.repo.CreateTenant(ctx, tenant)

	// Mock implementation
	return nil
}

// GetTenant retrieves a tenant by ID
func (s *tenantService) GetTenant(ctx context.Context, tenantID string) (*models.Tenant, error) {
	if tenantID == "" {
		return nil, errors.New("tenant ID is required")
	}

	// TODO: Get from database
	// return s.repo.GetTenant(ctx, tenantID)

	// Mock implementation
	return &models.Tenant{
		ID:       tenantID,
		Name:     "Example Client",
		Domain:   "example.com",
		Status:   "active",
		Plan:     "pro",
		MaxUsers: 1000,
		Settings: models.TenantSettings{
			AllowedOrigins: []string{"https://example.com"},
			EnableOAuth:    true,
			EnableMFA:      true,
			SessionTimeout: 60,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// UpdateTenant updates an existing tenant
func (s *tenantService) UpdateTenant(ctx context.Context, tenant *models.Tenant) error {
	if tenant.ID == "" {
		return errors.New("tenant ID is required")
	}

	tenant.UpdatedAt = time.Now()

	// TODO: Update in database
	// return s.repo.UpdateTenant(ctx, tenant)

	// Mock implementation
	return nil
}

// DeleteTenant deletes a tenant
func (s *tenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant ID is required")
	}

	// TODO: Delete from database
	// return s.repo.DeleteTenant(ctx, tenantID)

	// Mock implementation
	return nil
}

// ListTenants retrieves a list of tenants
func (s *tenantService) ListTenants(ctx context.Context, limit, offset int) ([]*models.Tenant, error) {
	// TODO: Get from database
	// return s.repo.ListTenants(ctx, limit, offset)

	// Mock implementation
	return []*models.Tenant{
		{
			ID:     "tenant-1",
			Name:   "Client A",
			Domain: "clienta.com",
			Status: "active",
			Plan:   "basic",
		},
		{
			ID:     "tenant-2",
			Name:   "Client B",
			Domain: "clientb.com",
			Status: "active",
			Plan:   "pro",
		},
	}, nil
}

// GetTenantStats retrieves usage statistics for a tenant
func (s *tenantService) GetTenantStats(ctx context.Context, tenantID string) (*models.TenantStats, error) {
	if tenantID == "" {
		return nil, errors.New("tenant ID is required")
	}

	// TODO: Get from database
	// return s.repo.GetTenantStats(ctx, tenantID)

	// Mock implementation
	return &models.TenantStats{
		TenantID:    tenantID,
		TotalUsers:  150,
		ActiveUsers: 120,
		TotalLogins: 1250,
		LastLoginAt: time.Now(),
		StorageUsed: 1024 * 1024 * 50, // 50MB
		APIRequests: 5000,
		UpdatedAt:   time.Now(),
	}, nil
}

// ValidateTenantAccess validates if a tenant can access the service
func (s *tenantService) ValidateTenantAccess(ctx context.Context, tenantID string) error {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Check if tenant is active
	if tenant.Status != "active" {
		return fmt.Errorf("tenant is %s", tenant.Status)
	}

	// Check if tenant has expired
	if tenant.ExpiresAt != nil && time.Now().After(*tenant.ExpiresAt) {
		return errors.New("tenant subscription has expired")
	}

	// TODO: Check usage limits
	// stats, err := s.GetTenantStats(ctx, tenantID)
	// if err != nil {
	//     return err
	// }
	// if stats.TotalUsers >= tenant.MaxUsers {
	//     return errors.New("tenant has reached maximum user limit")
	// }

	return nil
}

// UpdateTenantStats updates usage statistics for a tenant
func (s *tenantService) UpdateTenantStats(ctx context.Context, stats *models.TenantStats) error {
	if stats.TenantID == "" {
		return errors.New("tenant ID is required")
	}

	stats.UpdatedAt = time.Now()

	// TODO: Update in database
	// return s.repo.UpdateTenantStats(ctx, stats)

	// Mock implementation
	return nil
}

// setDefaultSettings sets default tenant settings based on plan
func (s *tenantService) setDefaultSettings(tenant *models.Tenant) {
	switch tenant.Plan {
	case "basic":
		tenant.MaxUsers = 100
		tenant.Settings = models.TenantSettings{
			AllowedOrigins:   []string{fmt.Sprintf("https://%s", tenant.Domain)},
			CustomBranding:   false,
			EnableOAuth:      false,
			EnableMFA:        false,
			SessionTimeout:   30,
			MaxLoginAttempts: 5,
			EnableAuditLog:   false,
			PasswordPolicy: models.PasswordPolicy{
				MinLength:      8,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumbers: true,
				RequireSpecial: false,
				MaxAge:         90,
			},
		}
	case "pro":
		tenant.MaxUsers = 1000
		tenant.Settings = models.TenantSettings{
			AllowedOrigins:   []string{fmt.Sprintf("https://%s", tenant.Domain)},
			CustomBranding:   true,
			EnableOAuth:      true,
			EnableMFA:        true,
			SessionTimeout:   60,
			MaxLoginAttempts: 10,
			EnableAuditLog:   true,
			PasswordPolicy: models.PasswordPolicy{
				MinLength:      10,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumbers: true,
				RequireSpecial: true,
				MaxAge:         60,
			},
		}
	case "enterprise":
		tenant.MaxUsers = 10000
		tenant.Settings = models.TenantSettings{
			AllowedOrigins:   []string{fmt.Sprintf("https://%s", tenant.Domain)},
			CustomBranding:   true,
			EnableOAuth:      true,
			EnableMFA:        true,
			SessionTimeout:   120,
			MaxLoginAttempts: 15,
			EnableAuditLog:   true,
			PasswordPolicy: models.PasswordPolicy{
				MinLength:      12,
				RequireUpper:   true,
				RequireLower:   true,
				RequireNumbers: true,
				RequireSpecial: true,
				MaxAge:         30,
			},
		}
	default:
		// Default to basic plan
		tenant.Plan = "basic"
		s.setDefaultSettings(tenant)
	}
}

// AuthenticateTenant authenticates a tenant using client credentials
func (s *tenantService) AuthenticateTenant(ctx context.Context, req *models.TenantAuthRequest) (*models.TenantAuthResponse, error) {
	if req.GrantType != "client_credentials" {
		return nil, errors.New("unsupported grant type")
	}

	// Find tenant by client ID
	tenant, err := s.GetTenantByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials: %w", err)
	}

	// Validate client secret
	if tenant.ClientSecret != req.ClientSecret {
		return nil, errors.New("invalid client credentials")
	}

	// Validate tenant access
	if err := s.ValidateTenantAccess(ctx, tenant.ID); err != nil {
		return nil, fmt.Errorf("tenant access denied: %w", err)
	}

	// Generate tenant token
	accessToken, err := s.generateTenantToken(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken(tenant.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &models.TenantAuthResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: refreshToken,
		Scope:        "tenant:read tenant:write user:read user:write",
		TenantID:     tenant.ID,
		TenantName:   tenant.Name,
		Plan:         tenant.Plan,
	}, nil
}

// ValidateTenantToken validates a tenant token
func (s *tenantService) ValidateTenantToken(ctx context.Context, tokenString string) (*models.TenantToken, error) {
	// Parse and validate JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("tenant-secret-key"), nil // TODO: Use proper secret from config
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Validate token type
	if claims["type"] != "tenant" {
		return nil, errors.New("invalid token type")
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("token expired")
		}
	}

	tenantID, ok := claims["tenant_id"].(string)
	if !ok {
		return nil, errors.New("invalid tenant ID in token")
	}

	// Validate tenant still exists and is active
	if err := s.ValidateTenantAccess(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("tenant access denied: %w", err)
	}

	return &models.TenantToken{
		TenantID:  tenantID,
		Token:     tokenString,
		TokenType: "Bearer",
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
		Scope:     claims["scope"].(string),
		CreatedAt: time.Unix(int64(claims["iat"].(float64)), 0),
	}, nil
}

// RefreshTenantToken refreshes a tenant token
func (s *tenantService) RefreshTenantToken(ctx context.Context, refreshToken string) (*models.TenantAuthResponse, error) {
	// TODO: Implement refresh token validation
	// For now, we'll generate a new token

	// Extract tenant ID from refresh token (in real implementation, validate against stored refresh tokens)
	// This is a simplified implementation
	tenantID := "tenant-1234567890" // TODO: Extract from refresh token

	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Validate tenant access
	if err := s.ValidateTenantAccess(ctx, tenant.ID); err != nil {
		return nil, fmt.Errorf("tenant access denied: %w", err)
	}

	// Generate new access token
	accessToken, err := s.generateTenantToken(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Generate new refresh token
	newRefreshToken, err := s.generateRefreshToken(tenant.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &models.TenantAuthResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: newRefreshToken,
		Scope:        "tenant:read tenant:write user:read user:write",
		TenantID:     tenant.ID,
		TenantName:   tenant.Name,
		Plan:         tenant.Plan,
	}, nil
}

// RevokeTenantToken revokes a tenant token
func (s *tenantService) RevokeTenantToken(ctx context.Context, token string) error {
	// TODO: Implement token revocation (add to blacklist)
	// For now, just validate the token
	_, err := s.ValidateTenantToken(ctx, token)
	return err
}

// GetTenantByClientID retrieves a tenant by client ID
func (s *tenantService) GetTenantByClientID(ctx context.Context, clientID string) (*models.Tenant, error) {
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}

	// TODO: Get from database
	// return s.repo.GetTenantByClientID(ctx, clientID)

	// Mock implementation
	if clientID == "client-1234567890" {
		return &models.Tenant{
			ID:           "tenant-1234567890",
			Name:         "Acme Corp",
			Domain:       "acme.com",
			Status:       "active",
			Plan:         "pro",
			MaxUsers:     1000,
			ClientID:     "client-1234567890",
			ClientSecret: "secret-1234567890",
			Settings: models.TenantSettings{
				AllowedOrigins: []string{"https://acme.com"},
				EnableOAuth:    true,
				EnableMFA:      true,
				SessionTimeout: 60,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}, nil
	}

	return nil, errors.New("tenant not found")
}

// generateTenantToken generates a JWT token for tenant authentication
func (s *tenantService) generateTenantToken(tenant *models.Tenant) (string, error) {
	claims := jwt.MapClaims{
		"tenant_id": tenant.ID,
		"type":      "tenant",
		"scope":     "tenant:read tenant:write user:read user:write",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("tenant-secret-key")) // TODO: Use proper secret from config
}

// generateRefreshToken generates a refresh token
func (s *tenantService) generateRefreshToken(tenantID string) (string, error) {
	// Generate a random refresh token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
