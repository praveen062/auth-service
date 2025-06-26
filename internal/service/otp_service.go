package service

import (
	"auth-service/internal/config"
	"auth-service/internal/models"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// OTPService defines the interface for OTP operations
type OTPService interface {
	GenerateAndSendOTP(req *models.OTPRequest, config *models.TenantOTPConfig) (*models.OTPResponse, error)
	ValidateOTP(req *models.OTPVerifyRequest) (bool, error)
	GetTenantOTPConfig(tenantID string) (*models.TenantOTPConfig, error)
	UpdateUserOTPPreference(pref *models.UserOTPPreference) error
	GetSMSUsageInfo(tenantID string) (*models.SMSUsageInfo, error)
	ResetBillingCycle(tenantID string) error
	TriggerTwoFactorAuth(ctx context.Context, req *models.TwoFactorAuthRequest) (*models.TwoFactorAuthResponse, error)
	ValidateTenantOnboardingConfig(config *models.TenantOTPConfig) error
}

type otpService struct {
	store              map[string]*models.OTPRecord
	usage              map[string]*models.TenantOTPConfig // Track usage per tenant
	notificationClient NotificationClient
	subscriptionClient SubscriptionClient
	mu                 sync.Mutex
}

// NewOTPService creates a new OTP service with default configuration
func NewOTPService() OTPService {
	serviceConfig := config.DefaultServiceConfig()

	return &otpService{
		store:              make(map[string]*models.OTPRecord),
		usage:              make(map[string]*models.TenantOTPConfig),
		notificationClient: NewNotificationClient(serviceConfig.NotificationService),
		subscriptionClient: NewSubscriptionClient(serviceConfig.SubscriptionService),
	}
}

// NewOTPServiceWithConfig creates OTP service with custom configuration
func NewOTPServiceWithConfig(serviceConfig *config.ServiceConfig) OTPService {
	return &otpService{
		store:              make(map[string]*models.OTPRecord),
		usage:              make(map[string]*models.TenantOTPConfig),
		notificationClient: NewNotificationClient(serviceConfig.NotificationService),
		subscriptionClient: NewSubscriptionClient(serviceConfig.SubscriptionService),
	}
}

// NewOTPServiceWithClients creates OTP service with custom clients (for testing)
func NewOTPServiceWithClients(notificationClient NotificationClient, subscriptionClient SubscriptionClient) OTPService {
	return &otpService{
		store:              make(map[string]*models.OTPRecord),
		usage:              make(map[string]*models.TenantOTPConfig),
		notificationClient: notificationClient,
		subscriptionClient: subscriptionClient,
	}
}

// GenerateAndSendOTP generates and sends OTP based on field type and tenant configuration
func (s *otpService) GenerateAndSendOTP(req *models.OTPRequest, config *models.TenantOTPConfig) (*models.OTPResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate that at least one field is provided
	if req.Email == "" && req.Mobile == "" {
		return nil, models.CreateError(models.ErrorCodeMissingFields, "either email or mobile number is required")
	}

	// Determine field type and validate
	fieldType, err := s.determineFieldType(req)
	if err != nil {
		return nil, models.CreateError(models.ErrorCodeInvalidRequest, err.Error())
	}

	// Determine delivery method based on field type and tenant config
	deliveryMethod := s.determineDeliveryMethod(req, config, fieldType)

	// Validate that the chosen method is enabled for the tenant
	if !s.isDeliveryMethodEnabled(deliveryMethod, config) {
		return nil, models.CreateError(models.ErrorCodeFeatureDisabled,
			fmt.Sprintf("delivery method %s is not enabled for this tenant", deliveryMethod))
	}

	// Validate field type against tenant configuration
	if !s.isFieldTypeAllowed(fieldType, config) {
		return nil, models.CreateError(models.ErrorCodeFeatureDisabled,
			fmt.Sprintf("field type %s is not allowed for this tenant", fieldType))
	}

	// Check SMS limits if SMS delivery is requested
	if deliveryMethod == models.OTPDeliverySMS || deliveryMethod == models.OTPDeliveryBoth {
		if err := s.checkSMSLimit(config); err != nil {
			return nil, models.CreateError(models.ErrorCode2FAQuotaExceeded, err.Error())
		}
	}

	// Generate OTP with tenant-specific digit length
	code, digitLength, err := s.generateOTP(config)
	if err != nil {
		return nil, err
	}

	expirationMinutes := config.OTPExpirationMinutes
	if expirationMinutes == 0 {
		expirationMinutes = 5 // default 5 minutes
	}

	record := &models.OTPRecord{
		Email:          req.Email,
		Mobile:         req.Mobile,
		TenantID:       req.TenantID,
		Code:           code,
		DeliveryMethod: deliveryMethod,
		FieldType:      fieldType,
		ExpiresAt:      time.Now().Add(time.Duration(expirationMinutes) * time.Minute),
		Used:           false,
		CreatedAt:      time.Now(),
	}

	key := s.generateKey(req, fieldType)
	s.store[key] = record

	// Track usage and send OTP
	var smsUsageInfo *models.SMSUsageInfo
	switch deliveryMethod {
	case models.OTPDeliveryEmail:
		if fieldType == models.OTPFieldEmail {
			s.sendEmailOTP(req.Email, code, req.TenantID)
		} else {
			return nil, models.CreateError(models.ErrorCodeInvalidRequest, "email delivery method requires email field type")
		}
	case models.OTPDeliverySMS:
		if fieldType == models.OTPFieldMobile {
			s.sendSMSOTP(req.Mobile, code, req.TenantID)
			s.incrementSMSUsage(config)
			smsUsageInfo = s.getSMSUsageInfo(config)
		} else {
			return nil, models.CreateError(models.ErrorCodeInvalidRequest, "SMS delivery method requires mobile field type")
		}
	case models.OTPDeliveryBoth:
		if req.Email != "" {
			s.sendEmailOTP(req.Email, code, req.TenantID)
		}
		if req.Mobile != "" {
			s.sendSMSOTP(req.Mobile, code, req.TenantID)
			s.incrementSMSUsage(config)
			smsUsageInfo = s.getSMSUsageInfo(config)
		}
	}

	availableMethods := s.getAvailableMethods(config)
	availableFields := s.getAvailableFields(config)

	return &models.OTPResponse{
		Message:          fmt.Sprintf("OTP sent via %s to %s", deliveryMethod, fieldType),
		DeliveryMethod:   deliveryMethod,
		FieldType:        fieldType,
		ExpiresIn:        expirationMinutes * 60,
		OTPDigitLength:   digitLength,
		AvailableMethods: availableMethods,
		AvailableFields:  availableFields,
		SMSUsageInfo:     smsUsageInfo,
	}, nil
}

// ValidateOTP checks if the OTP is valid and not expired/used
func (s *otpService) ValidateOTP(req *models.OTPVerifyRequest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Determine field type from request
	fieldType, err := s.determineFieldTypeFromVerify(req)
	if err != nil {
		return false, err
	}

	key := s.generateKeyFromVerify(req, fieldType)
	record, ok := s.store[key]
	if !ok {
		return false, nil
	}

	if record.Used || time.Now().After(record.ExpiresAt) {
		return false, nil
	}

	if record.Code != req.Code {
		return false, nil
	}

	record.Used = true
	return true, nil
}

// GetTenantOTPConfig returns OTP configuration for a tenant
func (s *otpService) GetTenantOTPConfig(tenantID string) (*models.TenantOTPConfig, error) {
	// In real implementation, fetch from database
	// For demo, return default config based on tenant plan
	var config *models.TenantOTPConfig

	switch tenantID {
	case "tenant-basic":
		config = &models.TenantOTPConfig{
			TenantID:              tenantID,
			Plan:                  "basic",
			EnableEmailOTP:        true,
			EnableSMSOTP:          false,
			DefaultDeliveryMethod: models.OTPDeliveryEmail,
			AllowUserChoice:       false,
			AllowFieldChoice:      false,
			OTPExpirationMinutes:  5,
			OTPDigitLength:        4, // 4-digit OTP for basic plan
			MaxOTPAttempts:        3,
			RateLimitPerHour:      5,
			MonthlySMSLimit:       0, // No SMS for basic plan
			CurrentSMSUsage:       0,
			SMSCostPerMessage:     0.05,
			BillingCycleStart:     time.Now().Truncate(24 * time.Hour),
		}
	case "tenant-pro":
		config = &models.TenantOTPConfig{
			TenantID:              tenantID,
			Plan:                  "pro",
			EnableEmailOTP:        true,
			EnableSMSOTP:          true,
			DefaultDeliveryMethod: models.OTPDeliveryUserChoice,
			AllowUserChoice:       true,
			AllowFieldChoice:      true,
			OTPExpirationMinutes:  10,
			OTPDigitLength:        6, // 6-digit OTP for pro plan
			MaxOTPAttempts:        5,
			RateLimitPerHour:      10,
			MonthlySMSLimit:       1000, // 1000 SMS per month
			CurrentSMSUsage:       0,
			SMSCostPerMessage:     0.05,
			BillingCycleStart:     time.Now().Truncate(24 * time.Hour),
		}
	case "tenant-enterprise":
		config = &models.TenantOTPConfig{
			TenantID:              tenantID,
			Plan:                  "enterprise",
			EnableEmailOTP:        true,
			EnableSMSOTP:          true,
			DefaultDeliveryMethod: models.OTPDeliveryBoth,
			AllowUserChoice:       true,
			AllowFieldChoice:      true,
			OTPExpirationMinutes:  5,
			OTPDigitLength:        8, // 8-digit OTP for enterprise plan
			MaxOTPAttempts:        3,
			RateLimitPerHour:      20,
			MonthlySMSLimit:       10000, // 10,000 SMS per month
			CurrentSMSUsage:       0,
			SMSCostPerMessage:     0.05,
			BillingCycleStart:     time.Now().Truncate(24 * time.Hour),
		}
	default:
		// Default configuration for unknown tenants
		config = &models.TenantOTPConfig{
			TenantID:              tenantID,
			Plan:                  "default",
			EnableEmailOTP:        true,
			EnableSMSOTP:          false,
			DefaultDeliveryMethod: models.OTPDeliveryEmail,
			AllowUserChoice:       false,
			AllowFieldChoice:      false,
			OTPExpirationMinutes:  5,
			OTPDigitLength:        6, // Default 6-digit OTP
			MaxOTPAttempts:        3,
			RateLimitPerHour:      10,
			MonthlySMSLimit:       0,
			CurrentSMSUsage:       0,
			SMSCostPerMessage:     0.05,
			BillingCycleStart:     time.Now().Truncate(24 * time.Hour),
		}
	}

	// Validate the configuration before returning
	if err := s.validateTenantOTPConfig(config); err != nil {
		return nil, fmt.Errorf("invalid tenant OTP configuration for %s: %w", tenantID, err)
	}

	// Check if we need to reset billing cycle
	s.checkAndResetBillingCycle(config)

	// Load current usage from storage
	if storedConfig, exists := s.usage[tenantID]; exists {
		config.CurrentSMSUsage = storedConfig.CurrentSMSUsage
		config.BillingCycleStart = storedConfig.BillingCycleStart
	}

	return config, nil
}

// ValidateTenantOnboardingConfig validates OTP configuration during tenant onboarding
func (s *otpService) ValidateTenantOnboardingConfig(config *models.TenantOTPConfig) error {
	// Use the same validation logic
	if err := s.validateTenantOTPConfig(config); err != nil {
		return err
	}

	// Additional onboarding-specific validations
	if config.Plan == "" {
		return models.CreateError(models.ErrorCodeMissingFields, "plan is required for tenant onboarding")
	}

	// Ensure digit length is explicitly set (not defaulted)
	if config.OTPDigitLength == 0 {
		return models.CreateError(models.ErrorCodeMissingFields,
			"OTP digit length must be explicitly specified during tenant onboarding (cannot be 0)")
	}

	return nil
}

// GetSMSUsageInfo returns SMS usage information for a tenant
func (s *otpService) GetSMSUsageInfo(tenantID string) (*models.SMSUsageInfo, error) {
	config, err := s.GetTenantOTPConfig(tenantID)
	if err != nil {
		return nil, err
	}

	return s.getSMSUsageInfo(config), nil
}

// ResetBillingCycle resets the billing cycle for a tenant
func (s *otpService) ResetBillingCycle(tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if storedConfig, exists := s.usage[tenantID]; exists {
		storedConfig.CurrentSMSUsage = 0
		storedConfig.BillingCycleStart = time.Now().Truncate(24 * time.Hour)
		log.Printf("[OTP] Reset billing cycle for tenant %s", tenantID)
	}

	return nil
}

// UpdateUserOTPPreference updates user's OTP delivery preference
func (s *otpService) UpdateUserOTPPreference(pref *models.UserOTPPreference) error {
	// In real implementation, save to database
	pref.UpdatedAt = time.Now()
	log.Printf("[OTP] Updated user preference: %s prefers %s via %s", pref.UserID, pref.PreferredMethod, pref.PreferredField)
	return nil
}

// Helper methods
func (s *otpService) checkSMSLimit(config *models.TenantOTPConfig) error {
	if config.MonthlySMSLimit == 0 {
		return fmt.Errorf("SMS OTP is not available for %s plan", config.Plan)
	}

	if config.CurrentSMSUsage >= config.MonthlySMSLimit {
		return fmt.Errorf("monthly SMS limit of %d reached for %s plan", config.MonthlySMSLimit, config.Plan)
	}

	return nil
}

func (s *otpService) incrementSMSUsage(config *models.TenantOTPConfig) {
	// Store usage in memory (in real implementation, save to database)
	if storedConfig, exists := s.usage[config.TenantID]; exists {
		storedConfig.CurrentSMSUsage++
	} else {
		s.usage[config.TenantID] = &models.TenantOTPConfig{
			TenantID:          config.TenantID,
			CurrentSMSUsage:   1,
			BillingCycleStart: config.BillingCycleStart,
		}
	}

	log.Printf("[OTP] SMS usage incremented for tenant %s: %d/%d",
		config.TenantID, s.usage[config.TenantID].CurrentSMSUsage, config.MonthlySMSLimit)
}

func (s *otpService) getSMSUsageInfo(config *models.TenantOTPConfig) *models.SMSUsageInfo {
	currentUsage := 0
	if storedConfig, exists := s.usage[config.TenantID]; exists {
		currentUsage = storedConfig.CurrentSMSUsage
	}

	remaining := config.MonthlySMSLimit - currentUsage
	if remaining < 0 {
		remaining = 0
	}

	usagePercentage := 0.0
	if config.MonthlySMSLimit > 0 {
		usagePercentage = math.Round((float64(currentUsage) / float64(config.MonthlySMSLimit)) * 100)
	}

	billingCycleEnd := config.BillingCycleStart.AddDate(0, 1, 0)

	return &models.SMSUsageInfo{
		MonthlyLimit:    config.MonthlySMSLimit,
		CurrentUsage:    currentUsage,
		RemainingSMS:    remaining,
		UsagePercentage: usagePercentage,
		BillingCycleEnd: billingCycleEnd,
	}
}

func (s *otpService) checkAndResetBillingCycle(config *models.TenantOTPConfig) {
	// Check if billing cycle needs to be reset (monthly)
	now := time.Now()
	nextBillingCycle := config.BillingCycleStart.AddDate(0, 1, 0)

	if now.After(nextBillingCycle) {
		// Reset billing cycle
		if storedConfig, exists := s.usage[config.TenantID]; exists {
			storedConfig.CurrentSMSUsage = 0
			storedConfig.BillingCycleStart = now.Truncate(24 * time.Hour)
			log.Printf("[OTP] Billing cycle reset for tenant %s", config.TenantID)
		}
	}
}

func (s *otpService) determineFieldType(req *models.OTPRequest) (models.OTPFieldType, error) {
	// If user specified field type, validate it
	if req.FieldType != "" {
		if req.FieldType == models.OTPFieldEmail && req.Email == "" {
			return "", fmt.Errorf("email field type requires email address")
		}
		if req.FieldType == models.OTPFieldMobile && req.Mobile == "" {
			return "", fmt.Errorf("mobile field type requires mobile number")
		}
		return req.FieldType, nil
	}

	// Auto-determine based on provided fields
	if req.Email != "" && req.Mobile == "" {
		return models.OTPFieldEmail, nil
	}
	if req.Mobile != "" && req.Email == "" {
		return models.OTPFieldMobile, nil
	}
	if req.Email != "" && req.Mobile != "" {
		// Both provided, default to email unless user specified mobile
		return models.OTPFieldEmail, nil
	}

	return "", fmt.Errorf("either email or mobile number is required")
}

func (s *otpService) determineFieldTypeFromVerify(req *models.OTPVerifyRequest) (models.OTPFieldType, error) {
	// If user specified field type, validate it
	if req.FieldType != "" {
		if req.FieldType == models.OTPFieldEmail && req.Email == "" {
			return "", fmt.Errorf("email field type requires email address")
		}
		if req.FieldType == models.OTPFieldMobile && req.Mobile == "" {
			return "", fmt.Errorf("mobile field type requires mobile number")
		}
		return req.FieldType, nil
	}

	// Auto-determine based on provided fields
	if req.Email != "" && req.Mobile == "" {
		return models.OTPFieldEmail, nil
	}
	if req.Mobile != "" && req.Email == "" {
		return models.OTPFieldMobile, nil
	}
	if req.Email != "" && req.Mobile != "" {
		// Both provided, default to email unless user specified mobile
		return models.OTPFieldEmail, nil
	}

	return "", fmt.Errorf("either email or mobile number is required")
}

func (s *otpService) determineDeliveryMethod(req *models.OTPRequest, config *models.TenantOTPConfig, fieldType models.OTPFieldType) models.OTPDeliveryMethod {
	// If user specified a method and it's allowed
	if req.DeliveryMethod != "" && s.isDeliveryMethodEnabled(req.DeliveryMethod, config) {
		return req.DeliveryMethod
	}

	// Auto-determine based on field type and tenant config
	switch fieldType {
	case models.OTPFieldEmail:
		if config.EnableEmailOTP {
			return models.OTPDeliveryEmail
		}
	case models.OTPFieldMobile:
		if config.EnableSMSOTP {
			return models.OTPDeliverySMS
		}
	}

	// Use tenant default
	return config.DefaultDeliveryMethod
}

func (s *otpService) isDeliveryMethodEnabled(method models.OTPDeliveryMethod, config *models.TenantOTPConfig) bool {
	switch method {
	case models.OTPDeliveryEmail:
		return config.EnableEmailOTP
	case models.OTPDeliverySMS:
		return config.EnableSMSOTP
	case models.OTPDeliveryBoth:
		return config.EnableEmailOTP && config.EnableSMSOTP
	case models.OTPDeliveryUserChoice:
		return config.AllowUserChoice
	default:
		return false
	}
}

func (s *otpService) isFieldTypeAllowed(fieldType models.OTPFieldType, config *models.TenantOTPConfig) bool {
	switch fieldType {
	case models.OTPFieldEmail:
		return config.EnableEmailOTP
	case models.OTPFieldMobile:
		return config.EnableSMSOTP
	default:
		return false
	}
}

func (s *otpService) getAvailableMethods(config *models.TenantOTPConfig) []models.OTPDeliveryMethod {
	var methods []models.OTPDeliveryMethod
	if config.EnableEmailOTP {
		methods = append(methods, models.OTPDeliveryEmail)
	}
	if config.EnableSMSOTP {
		methods = append(methods, models.OTPDeliverySMS)
	}
	if config.EnableEmailOTP && config.EnableSMSOTP {
		methods = append(methods, models.OTPDeliveryBoth)
	}
	if config.AllowUserChoice {
		methods = append(methods, models.OTPDeliveryUserChoice)
	}
	return methods
}

func (s *otpService) getAvailableFields(config *models.TenantOTPConfig) []models.OTPFieldType {
	var fields []models.OTPFieldType
	if config.EnableEmailOTP {
		fields = append(fields, models.OTPFieldEmail)
	}
	if config.EnableSMSOTP {
		fields = append(fields, models.OTPFieldMobile)
	}
	return fields
}

func (s *otpService) generateKey(req *models.OTPRequest, fieldType models.OTPFieldType) string {
	switch fieldType {
	case models.OTPFieldEmail:
		return req.Email + ":" + req.TenantID
	case models.OTPFieldMobile:
		return req.Mobile + ":" + req.TenantID
	default:
		return req.Email + ":" + req.TenantID
	}
}

func (s *otpService) generateKeyFromVerify(req *models.OTPVerifyRequest, fieldType models.OTPFieldType) string {
	switch fieldType {
	case models.OTPFieldEmail:
		return req.Email + ":" + req.TenantID
	case models.OTPFieldMobile:
		return req.Mobile + ":" + req.TenantID
	default:
		return req.Email + ":" + req.TenantID
	}
}

func (s *otpService) sendEmailOTP(email, code, tenantID string) {
	// For demo: log to console (replace with email service)
	log.Printf("[OTP-EMAIL] Sent OTP %s to %s (tenant: %s)", code, email, tenantID)
}

func (s *otpService) sendSMSOTP(mobile, code, tenantID string) {
	// For demo: log to console (replace with SMS service)
	log.Printf("[OTP-SMS] Sent OTP %s to %s (tenant: %s)", code, mobile, tenantID)
}

func randomInt(min, max int) int {
	b := make([]byte, 2)
	rand.Read(b)
	return min + int(b[0])%((max-min)+1)
}

// TriggerTwoFactorAuth triggers 2FA via Notification Service with subscription validation
func (s *otpService) TriggerTwoFactorAuth(ctx context.Context, req *models.TwoFactorAuthRequest) (*models.TwoFactorAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate required fields using map-based validation
	if err := s.validateTwoFactorRequest(req); err != nil {
		return nil, err
	}

	// Get channel information using map lookup
	feature, channelType, valid := models.GetChannelInfo(req.Channel)
	if !valid {
		return nil, models.CreateError(models.ErrorCodeInvalidChannel,
			fmt.Sprintf("Invalid channel: %s. Valid channels: %v", req.Channel, models.ValidChannels()))
	}

	// Validate subscription and quota
	subscriptionResp, err := s.validateSubscription(ctx, req.ClientID, feature)
	if err != nil {
		return nil, err
	}

	// Check subscription validation results using map-based error handling
	if err := s.checkSubscriptionValidation(subscriptionResp, req.Channel); err != nil {
		return nil, err
	}

	// Get tenant config for OTP settings
	config, err := s.GetTenantOTPConfig(req.ClientID)
	if err != nil {
		return nil, models.CreateError(models.ErrorCodeInternalError,
			fmt.Sprintf("failed to get tenant config: %v", err))
	}

	// Generate OTP with tenant-specific digit length
	code, digitLength, err := s.generateOTP(config)
	if err != nil {
		return nil, err
	}

	// Store OTP record
	record, err := s.createOTPRecord(req, code, channelType, config)
	if err != nil {
		return nil, err
	}

	// Store OTP with key based on recipient and client
	key := req.Recipient + ":" + req.ClientID
	s.store[key] = record

	// Prepare and send notification
	notificationResp, err := s.sendNotification(ctx, req, code, channelType, config)
	if err != nil {
		// Remove the stored OTP since notification failed
		delete(s.store, key)
		return nil, err
	}

	// Log the 2FA trigger
	log.Printf("[2FA] Triggered %s 2FA for user %s (client: %s, message_id: %s)",
		req.Channel, req.UserID, req.ClientID, notificationResp.MessageID)

	return &models.TwoFactorAuthResponse{
		Success:        true,
		Message:        fmt.Sprintf("2FA code sent via %s", req.Channel),
		OTPDigitLength: digitLength,
		ExpiresIn:      config.OTPExpirationMinutes * 60, // Convert to seconds
		MessageID:      notificationResp.MessageID,
	}, nil
}

// validateTwoFactorRequest validates the 2FA request
func (s *otpService) validateTwoFactorRequest(req *models.TwoFactorAuthRequest) error {
	// Use map for required field validation
	requiredFields := map[string]string{
		"user_id":   req.UserID,
		"client_id": req.ClientID,
		"channel":   req.Channel,
		"recipient": req.Recipient,
	}

	for field, value := range requiredFields {
		if value == "" {
			return models.CreateError(models.ErrorCodeMissingFields,
				fmt.Sprintf("Missing required field: %s", field))
		}
	}

	return nil
}

// validateSubscription validates subscription with the subscription service
func (s *otpService) validateSubscription(ctx context.Context, clientID, feature string) (*models.SubscriptionValidationResponse, error) {
	subscriptionReq := &models.SubscriptionValidationRequest{
		ClientID: clientID,
		Feature:  feature,
	}

	subscriptionResp, err := s.subscriptionClient.ValidateSubscription(ctx, subscriptionReq)
	if err != nil {
		return nil, models.CreateError(models.ErrorCodeServiceUnavailable,
			fmt.Sprintf("subscription validation failed: %v", err))
	}

	return subscriptionResp, nil
}

// checkSubscriptionValidation checks subscription validation results
func (s *otpService) checkSubscriptionValidation(resp *models.SubscriptionValidationResponse, channel string) error {
	// Use map for validation checks
	validationChecks := map[string]struct {
		condition bool
		errorCode models.ErrorCode
		message   string
	}{
		"subscription_valid": {
			condition: resp.Valid,
			errorCode: models.ErrorCodeInvalidSubscription,
			message:   "Client subscription is invalid",
		},
		"feature_enabled": {
			condition: resp.FeatureEnabled,
			errorCode: models.ErrorCodeFeatureDisabled,
			message:   fmt.Sprintf("2FA %s feature is not enabled for this client", channel),
		},
		"quota_available": {
			condition: resp.QuotaAvailable,
			errorCode: models.ErrorCode2FAQuotaExceeded,
			message:   fmt.Sprintf("The client's %s 2FA quota has been exceeded", channel),
		},
	}

	for _, check := range validationChecks {
		if !check.condition {
			return models.CreateError(check.errorCode, check.message)
		}
	}

	return nil
}

// generateOTP generates OTP with tenant-specific digit length
func (s *otpService) generateOTP(config *models.TenantOTPConfig) (string, int, error) {
	digitLength := config.OTPDigitLength

	// Load system configuration for defaults and validation
	const (
		MinDigitLength = 4
		MaxDigitLength = 10
	)

	// STRICT VALIDATION - No fallbacks, configuration MUST be valid
	if digitLength <= 0 {
		return "", 0, models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("OTP digit length cannot be 0 or negative, got %d", digitLength))
	}

	// Validate digit length range
	if digitLength < MinDigitLength || digitLength > MaxDigitLength {
		return "", 0, models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("invalid OTP digit length: %d (must be between %d and %d)",
				digitLength, MinDigitLength, MaxDigitLength))
	}

	// Calculate min and max values for the digit length
	min := int(math.Pow10(digitLength - 1))
	max := int(math.Pow10(digitLength)) - 1
	code := fmt.Sprintf("%0*d", digitLength, randomInt(min, max))

	return code, digitLength, nil
}

// createOTPRecord creates an OTP record
func (s *otpService) createOTPRecord(req *models.TwoFactorAuthRequest, code, channelType string, config *models.TenantOTPConfig) (*models.OTPRecord, error) {
	// Set expiration time
	expirationMinutes := config.OTPExpirationMinutes
	if expirationMinutes == 0 {
		expirationMinutes = 5 // default 5 minutes
	}

	// Use map for delivery method mapping
	deliveryMethodMap := map[string]models.OTPDeliveryMethod{
		"EMAIL": models.OTPDeliveryEmail,
		"SMS":   models.OTPDeliverySMS,
	}

	// Use map for field type mapping
	fieldTypeMap := map[string]models.OTPFieldType{
		"EMAIL": models.OTPFieldEmail,
		"SMS":   models.OTPFieldMobile,
	}

	deliveryMethod, ok := deliveryMethodMap[channelType]
	if !ok {
		return nil, models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("invalid channel type: %s", channelType))
	}

	fieldType, ok := fieldTypeMap[channelType]
	if !ok {
		return nil, models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("invalid channel type: %s", channelType))
	}

	record := &models.OTPRecord{
		Email:          req.Recipient, // For both email and SMS, store in email field
		Mobile:         req.Recipient, // For both email and SMS, store in mobile field
		TenantID:       req.ClientID,
		Code:           code,
		DeliveryMethod: deliveryMethod,
		FieldType:      fieldType,
		ExpiresAt:      time.Now().Add(time.Duration(expirationMinutes) * time.Minute),
		Used:           false,
		CreatedAt:      time.Now(),
	}

	return record, nil
}

// sendNotification sends notification via the notification service
func (s *otpService) sendNotification(ctx context.Context, req *models.TwoFactorAuthRequest, code, channelType string, config *models.TenantOTPConfig) (*models.NotificationResponse, error) {
	// Prepare notification payload
	expiryUnit := models.ExpiryUnitMinutes
	expiryValue := config.OTPExpirationMinutes
	if expiryValue >= 60 {
		expiryUnit = models.ExpiryUnitHours
		expiryValue = expiryValue / 60
	}

	variables := map[string]interface{}{
		"otp":          code,
		"user_name":    req.UserName,
		"expiry_value": expiryValue,
		"expiry_unit":  expiryUnit,
		"client_name":  req.ClientID, // In real implementation, get actual client name
	}

	notificationPayload := &models.NotificationPayload{
		ClientID:   req.ClientID,
		Channel:    models.NotificationChannel(channelType),
		TemplateID: "2FA_CODE",
		Recipient:  req.Recipient,
		Variables:  variables,
	}

	// Send notification
	notificationResp, err := s.notificationClient.SendNotification(ctx, notificationPayload)
	if err != nil {
		return nil, models.CreateError(models.ErrorCodeServiceUnavailable,
			fmt.Sprintf("failed to send notification: %v", err))
	}

	return notificationResp, nil
}

// validateTenantOTPConfig validates tenant OTP configuration
func (s *otpService) validateTenantOTPConfig(config *models.TenantOTPConfig) error {
	const (
		MinDigitLength = 4
		MaxDigitLength = 10
	)

	// Validate required fields
	if config.TenantID == "" {
		return models.CreateError(models.ErrorCodeMissingFields, "tenant_id is required")
	}

	// Validate digit length - MUST be within acceptable range, never 0
	if config.OTPDigitLength <= 0 {
		return models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("OTP digit length cannot be 0 or negative, got %d", config.OTPDigitLength))
	}

	if config.OTPDigitLength < MinDigitLength || config.OTPDigitLength > MaxDigitLength {
		return models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("OTP digit length must be between %d and %d, got %d",
				MinDigitLength, MaxDigitLength, config.OTPDigitLength))
	}

	// Validate expiration time
	if config.OTPExpirationMinutes <= 0 {
		return models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("OTP expiration minutes must be positive, got %d", config.OTPExpirationMinutes))
	}

	// Validate max attempts
	if config.MaxOTPAttempts <= 0 {
		return models.CreateError(models.ErrorCodeInvalidRequest,
			fmt.Sprintf("max OTP attempts must be positive, got %d", config.MaxOTPAttempts))
	}

	// Validate at least one delivery method is enabled
	if !config.EnableEmailOTP && !config.EnableSMSOTP {
		return models.CreateError(models.ErrorCodeFeatureDisabled,
			"at least one OTP delivery method (email or SMS) must be enabled")
	}

	return nil
}
