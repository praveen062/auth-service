package models

import "time"

// OTPDeliveryMethod represents how OTP should be delivered
type OTPDeliveryMethod string

const (
	OTPDeliveryEmail      OTPDeliveryMethod = "email"
	OTPDeliverySMS        OTPDeliveryMethod = "sms"
	OTPDeliveryBoth       OTPDeliveryMethod = "both"
	OTPDeliveryUserChoice OTPDeliveryMethod = "user_choice"
)

// OTPFieldType represents the type of field provided for OTP
type OTPFieldType string

const (
	OTPFieldEmail  OTPFieldType = "email"
	OTPFieldMobile OTPFieldType = "mobile"
)

// OTPRequest represents a request to send an OTP to a user
type OTPRequest struct {
	Email          string            `json:"email,omitempty"`  // Optional: email address
	Mobile         string            `json:"mobile,omitempty"` // Optional: mobile number
	TenantID       string            `json:"tenant_id" binding:"required"`
	DeliveryMethod OTPDeliveryMethod `json:"delivery_method,omitempty"` // For user choice
	FieldType      OTPFieldType      `json:"field_type,omitempty"`      // Which field to use (email/mobile)
}

// OTPVerifyRequest represents a request to verify an OTP
type OTPVerifyRequest struct {
	Email          string            `json:"email,omitempty"`  // Optional: email address
	Mobile         string            `json:"mobile,omitempty"` // Optional: mobile number
	TenantID       string            `json:"tenant_id" binding:"required"`
	Code           string            `json:"code" binding:"required"`
	DeliveryMethod OTPDeliveryMethod `json:"delivery_method,omitempty"` // Which method was used
	FieldType      OTPFieldType      `json:"field_type,omitempty"`      // Which field was used
}

// OTPRecord represents a stored OTP for a user
type OTPRecord struct {
	Email          string            `json:"email,omitempty"`
	Mobile         string            `json:"mobile,omitempty"`
	TenantID       string            `json:"tenant_id"`
	Code           string            `json:"code"`
	DeliveryMethod OTPDeliveryMethod `json:"delivery_method"`
	FieldType      OTPFieldType      `json:"field_type"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Used           bool              `json:"used"`
	CreatedAt      time.Time         `json:"created_at"`
}

// TenantOTPConfig represents OTP configuration for a tenant
type TenantOTPConfig struct {
	TenantID              string            `json:"tenant_id"`
	Plan                  string            `json:"plan"` // basic, pro, enterprise
	EnableEmailOTP        bool              `json:"enable_email_otp"`
	EnableSMSOTP          bool              `json:"enable_sms_otp"`
	DefaultDeliveryMethod OTPDeliveryMethod `json:"default_delivery_method"`
	AllowUserChoice       bool              `json:"allow_user_choice"`
	AllowFieldChoice      bool              `json:"allow_field_choice"` // Allow users to choose email or mobile
	OTPExpirationMinutes  int               `json:"otp_expiration_minutes"`
	OTPDigitLength        int               `json:"otp_digit_length"` // Number of digits in OTP (4, 6, 8, etc.)
	MaxOTPAttempts        int               `json:"max_otp_attempts"`
	RateLimitPerHour      int               `json:"rate_limit_per_hour"`

	// SMS Limits
	MonthlySMSLimit   int       `json:"monthly_sms_limit"`    // Monthly SMS OTP limit
	CurrentSMSUsage   int       `json:"current_sms_usage"`    // Current month SMS usage
	SMSCostPerMessage float64   `json:"sms_cost_per_message"` // Cost per SMS (for billing)
	BillingCycleStart time.Time `json:"billing_cycle_start"`  // When billing cycle resets
}

// OTPResponse represents the response for OTP requests
type OTPResponse struct {
	Message          string              `json:"message"`
	DeliveryMethod   OTPDeliveryMethod   `json:"delivery_method"`
	FieldType        OTPFieldType        `json:"field_type"`
	ExpiresIn        int                 `json:"expires_in"`       // seconds
	OTPDigitLength   int                 `json:"otp_digit_length"` // Number of digits in the OTP
	AvailableMethods []OTPDeliveryMethod `json:"available_methods,omitempty"`
	AvailableFields  []OTPFieldType      `json:"available_fields,omitempty"`

	// SMS Usage Info (only for SMS delivery)
	SMSUsageInfo *SMSUsageInfo `json:"sms_usage_info,omitempty"`
}

// SMSUsageInfo provides information about SMS usage and limits
type SMSUsageInfo struct {
	MonthlyLimit    int       `json:"monthly_limit"`
	CurrentUsage    int       `json:"current_usage"`
	RemainingSMS    int       `json:"remaining_sms"`
	UsagePercentage float64   `json:"usage_percentage"`
	BillingCycleEnd time.Time `json:"billing_cycle_end"`
}

// UserOTPPreference represents user's OTP delivery preference
type UserOTPPreference struct {
	UserID          string            `json:"user_id"`
	TenantID        string            `json:"tenant_id"`
	PreferredMethod OTPDeliveryMethod `json:"preferred_method"`
	PreferredField  OTPFieldType      `json:"preferred_field"` // email or mobile
	Email           string            `json:"email,omitempty"`
	Mobile          string            `json:"mobile,omitempty"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// OTPUsageRecord represents a record of OTP usage for tracking
type OTPUsageRecord struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	UserID         string            `json:"user_id,omitempty"`
	Email          string            `json:"email,omitempty"`
	Mobile         string            `json:"mobile,omitempty"`
	DeliveryMethod OTPDeliveryMethod `json:"delivery_method"`
	FieldType      OTPFieldType      `json:"field_type"`
	Success        bool              `json:"success"`
	Cost           float64           `json:"cost,omitempty"` // For SMS billing
	CreatedAt      time.Time         `json:"created_at"`
}

// NotificationPayload represents the payload sent to Notification Service
type NotificationPayload struct {
	ClientID   string                 `json:"client_id"`
	Channel    NotificationChannel    `json:"channel"`
	TemplateID string                 `json:"template_id"`
	Recipient  string                 `json:"recipient"`
	Variables  map[string]interface{} `json:"variables"`
}

// NotificationChannel represents the notification delivery channel
type NotificationChannel string

const (
	NotificationChannelSMS   NotificationChannel = "SMS"
	NotificationChannelEmail NotificationChannel = "EMAIL"
)

// NotificationResponse represents the response from Notification Service
type NotificationResponse struct {
	Success   bool   `json:"success"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SubscriptionValidationRequest represents a request to validate subscription
type SubscriptionValidationRequest struct {
	ClientID string `json:"client_id"`
	Feature  string `json:"feature"` // "2FA_EMAIL" or "2FA_SMS"
}

// SubscriptionValidationResponse represents the response from Subscription Service
type SubscriptionValidationResponse struct {
	Valid          bool   `json:"valid"`
	FeatureEnabled bool   `json:"feature_enabled"`
	QuotaAvailable bool   `json:"quota_available"`
	DailyQuota     int    `json:"daily_quota"`
	MonthlyQuota   int    `json:"monthly_quota"`
	DailyUsage     int    `json:"daily_usage"`
	MonthlyUsage   int    `json:"monthly_usage"`
	Error          string `json:"error,omitempty"`
}

// TwoFactorAuthRequest represents a request to trigger 2FA
type TwoFactorAuthRequest struct {
	UserID    string `json:"user_id" binding:"required"`
	ClientID  string `json:"client_id" binding:"required"`
	Channel   string `json:"channel" binding:"required"` // "EMAIL" or "SMS"
	Recipient string `json:"recipient" binding:"required"`
	UserName  string `json:"user_name,omitempty"`
}

// TwoFactorAuthResponse represents the response for 2FA requests
type TwoFactorAuthResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	OTPDigitLength int    `json:"otp_digit_length"`
	ExpiresIn      int    `json:"expires_in"` // seconds
	MessageID      string `json:"message_id,omitempty"`
	Error          string `json:"error,omitempty"`
}

// ExpiryUnit represents the unit for OTP expiration time
type ExpiryUnit string

const (
	ExpiryUnitSeconds ExpiryUnit = "SECONDS"
	ExpiryUnitMinutes ExpiryUnit = "MINUTES"
	ExpiryUnitHours   ExpiryUnit = "HOURS"
)
