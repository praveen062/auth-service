package models

import (
	"time"
)

// MFAConfig represents a user's MFA configuration
type MFAConfig struct {
	UserID      string    `json:"user_id" db:"user_id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	Secret      string    `json:"secret" db:"secret"` // TOTP secret (encrypted)
	Enabled     bool      `json:"enabled" db:"enabled"`
	BackupCodes []string  `json:"backup_codes,omitempty" db:"backup_codes"` // Encrypted backup codes
	LastUsed    time.Time `json:"last_used,omitempty" db:"last_used"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// MFASetupRequest represents a request to setup MFA
type MFASetupRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
}

// MFASetupResponse represents the response for MFA setup
type MFASetupResponse struct {
	Secret      string   `json:"secret"`       // TOTP secret for manual entry
	QRCodeURL   string   `json:"qr_code_url"`  // URL to QR code image
	BackupCodes []string `json:"backup_codes"` // Backup codes for recovery
	Message     string   `json:"message"`
}

// MFAVerifyRequest represents a request to verify MFA code
type MFAVerifyRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
	Code     string `json:"code" binding:"required"` // TOTP code or backup code
}

// MFAEnableRequest represents a request to enable MFA
type MFAEnableRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
	Code     string `json:"code" binding:"required"` // First TOTP code to verify setup
}

// MFADisableRequest represents a request to disable MFA
type MFADisableRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
	Code     string `json:"code" binding:"required"` // Current TOTP code to verify
}

// MFABackupCodeRequest represents a request to use backup code
type MFABackupCodeRequest struct {
	UserID     string `json:"user_id" binding:"required"`
	TenantID   string `json:"tenant_id" binding:"required"`
	BackupCode string `json:"backup_code" binding:"required"`
}

// MFARegenerateBackupCodesRequest represents a request to regenerate backup codes
type MFARegenerateBackupCodesRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	TenantID string `json:"tenant_id" binding:"required"`
	Code     string `json:"code" binding:"required"` // Current TOTP code to verify
}

// MFARegenerateBackupCodesResponse represents the response for regenerated backup codes
type MFARegenerateBackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
	Message     string   `json:"message"`
}

// MFAStatus represents the current MFA status for a user
type MFAStatus struct {
	UserID               string    `json:"user_id"`
	TenantID             string    `json:"tenant_id"`
	Enabled              bool      `json:"enabled"`
	LastUsed             time.Time `json:"last_used,omitempty"`
	BackupCodesRemaining int       `json:"backup_codes_remaining"`
	CreatedAt            time.Time `json:"created_at"`
}

// MFAAttempt represents an MFA verification attempt
type MFAAttempt struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	Code      string    `json:"code" db:"code"` // Masked code for audit
	Success   bool      `json:"success" db:"success"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// MFALoginRequest represents a login request that may require MFA
type MFALoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	TenantID string `json:"tenant_id"`          // Optional, can be extracted from context
	MFACode  string `json:"mfa_code,omitempty"` // Optional, for MFA-enabled users
}

// MFALoginResponse represents a login response that may require MFA
type MFALoginResponse struct {
	RequiresMFA bool       `json:"requires_mfa"`
	AccessToken string     `json:"access_token,omitempty"`
	User        *User      `json:"user,omitempty"`
	MFAPrompt   *MFAPrompt `json:"mfa_prompt,omitempty"`
}

// MFAPrompt represents a prompt for MFA verification
type MFAPrompt struct {
	UserID           string `json:"user_id"`
	Message          string `json:"message"`
	AllowBackupCodes bool   `json:"allow_backup_codes"`
}
