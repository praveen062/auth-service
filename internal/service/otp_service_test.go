package service

import (
	"auth-service/internal/models"
	"context"
	"fmt"
	"testing"

	"github.com/sony/gobreaker"
)

func TestTenantBasedOTPDigitLength(t *testing.T) {
	service := NewOTPService()

	tests := []struct {
		name        string
		tenantID    string
		expectedLen int
	}{
		{
			name:        "Basic tenant should have 4-digit OTP",
			tenantID:    "tenant-basic",
			expectedLen: 4,
		},
		{
			name:        "Pro tenant should have 6-digit OTP",
			tenantID:    "tenant-pro",
			expectedLen: 6,
		},
		{
			name:        "Enterprise tenant should have 8-digit OTP",
			tenantID:    "tenant-enterprise",
			expectedLen: 8,
		},
		{
			name:        "Unknown tenant should default to 6-digit OTP",
			tenantID:    "unknown-tenant",
			expectedLen: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get tenant config
			config, err := service.GetTenantOTPConfig(tt.tenantID)
			if err != nil {
				t.Fatalf("Failed to get tenant config: %v", err)
			}

			// Verify digit length
			if config.OTPDigitLength != tt.expectedLen {
				t.Errorf("Expected OTP digit length %d, got %d", tt.expectedLen, config.OTPDigitLength)
			}

			// Test OTP generation
			req := &models.OTPRequest{
				Email:    "test@example.com",
				TenantID: tt.tenantID,
			}

			resp, err := service.GenerateAndSendOTP(req, config)
			if err != nil {
				t.Fatalf("Failed to generate OTP: %v", err)
			}

			// Verify response includes correct digit length
			if resp.OTPDigitLength != tt.expectedLen {
				t.Errorf("Response OTP digit length %d, expected %d", resp.OTPDigitLength, tt.expectedLen)
			}

			// Verify OTP code has correct length
			// We can't directly access the generated code, but we can verify the response message
			// indicates the correct delivery method and field type
			if resp.DeliveryMethod != models.OTPDeliveryEmail {
				t.Errorf("Expected delivery method %s, got %s", models.OTPDeliveryEmail, resp.DeliveryMethod)
			}
		})
	}
}

func TestOTPDigitLengthValidation(t *testing.T) {
	service := NewOTPService()

	// Test invalid digit lengths
	invalidLengths := []int{0, 1, 2, 3, 11, 15}

	for _, length := range invalidLengths {
		t.Run(fmt.Sprintf("Invalid length %d", length), func(t *testing.T) {
			config := &models.TenantOTPConfig{
				TenantID:       "test-tenant",
				OTPDigitLength: length,
				EnableEmailOTP: true,
			}

			req := &models.OTPRequest{
				Email:    "test@example.com",
				TenantID: "test-tenant",
			}

			_, err := service.GenerateAndSendOTP(req, config)
			if err == nil {
				t.Errorf("Expected error for invalid digit length %d, but got none", length)
			}
		})
	}

	// Test valid digit lengths
	validLengths := []int{4, 6, 8, 10}

	for _, length := range validLengths {
		t.Run(fmt.Sprintf("Valid length %d", length), func(t *testing.T) {
			config := &models.TenantOTPConfig{
				TenantID:       "test-tenant",
				OTPDigitLength: length,
				EnableEmailOTP: true,
			}

			req := &models.OTPRequest{
				Email:    "test@example.com",
				TenantID: "test-tenant",
			}

			resp, err := service.GenerateAndSendOTP(req, config)
			if err != nil {
				t.Errorf("Unexpected error for valid digit length %d: %v", length, err)
			}

			if resp.OTPDigitLength != length {
				t.Errorf("Expected OTP digit length %d, got %d", length, resp.OTPDigitLength)
			}
		})
	}
}

func TestOTPGenerationWithDifferentLengths(t *testing.T) {
	service := NewOTPService()

	// Test OTP generation for different lengths
	testCases := []struct {
		length int
		min    int
		max    int
	}{
		{4, 1000, 9999},
		{6, 100000, 999999},
		{8, 10000000, 99999999},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Length %d", tc.length), func(t *testing.T) {
			config := &models.TenantOTPConfig{
				TenantID:       "test-tenant",
				OTPDigitLength: tc.length,
				EnableEmailOTP: true,
			}

			req := &models.OTPRequest{
				Email:    "test@example.com",
				TenantID: "test-tenant",
			}

			resp, err := service.GenerateAndSendOTP(req, config)
			if err != nil {
				t.Fatalf("Failed to generate OTP: %v", err)
			}

			// Verify the response
			if resp.OTPDigitLength != tc.length {
				t.Errorf("Expected digit length %d, got %d", tc.length, resp.OTPDigitLength)
			}

			// Verify OTP validation works
			verifyReq := &models.OTPVerifyRequest{
				Email:    "test@example.com",
				TenantID: "test-tenant",
				Code:     "123456", // This should fail since we don't know the actual code
			}

			valid, err := service.ValidateOTP(verifyReq)
			if err != nil {
				t.Errorf("Unexpected error during validation: %v", err)
			}

			// Should be false since we're using a wrong code
			if valid {
				t.Error("Expected validation to fail with wrong code")
			}
		})
	}
}

func TestTriggerTwoFactorAuth(t *testing.T) {
	// Create mock clients
	mockNotificationClient := &MockNotificationClient{
		CircuitBreakerState: gobreaker.StateClosed,
	}
	mockSubscriptionClient := &MockSubscriptionClient{
		CircuitBreakerState: gobreaker.StateClosed,
	}

	// Create OTP service with mock clients
	service := NewOTPServiceWithClients(mockNotificationClient, mockSubscriptionClient)

	// Test successful 2FA trigger
	t.Run("Successful 2FA trigger", func(t *testing.T) {
		// Mock subscription validation success
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return &models.SubscriptionValidationResponse{
				Valid:          true,
				FeatureEnabled: true,
				QuotaAvailable: true,
			}, nil
		}

		// Mock notification success
		mockNotificationClient.SendNotificationFunc = func(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error) {
			return &models.NotificationResponse{
				Success:   true,
				MessageID: "test-message-id",
			}, nil
		}

		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "EMAIL",
			Recipient: "user@example.com",
			UserName:  "John Doe",
		}

		resp, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if !resp.Success {
			t.Errorf("Expected success=true, got %v", resp.Success)
		}

		if resp.MessageID != "test-message-id" {
			t.Errorf("Expected message_id=test-message-id, got %s", resp.MessageID)
		}

		if resp.OTPDigitLength != 6 { // tenant-pro has 6 digits
			t.Errorf("Expected OTP digit length=6, got %d", resp.OTPDigitLength)
		}
	})

	// Test invalid subscription
	t.Run("Invalid subscription", func(t *testing.T) {
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return &models.SubscriptionValidationResponse{
				Valid:          false,
				FeatureEnabled: true,
				QuotaAvailable: true,
			}, nil
		}

		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "EMAIL",
			Recipient: "user@example.com",
		}

		_, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err == nil {
			t.Fatalf("Expected error for invalid subscription, got none")
		}

		// Check if it's a structured API error
		if apiError, ok := err.(*models.APIError); ok {
			if apiError.Code != models.ErrorCodeInvalidSubscription {
				t.Errorf("Expected error code %s, got %s", models.ErrorCodeInvalidSubscription, apiError.Code)
			}
		} else {
			t.Errorf("Expected APIError, got %T", err)
		}
	})

	// Test feature disabled
	t.Run("Feature disabled", func(t *testing.T) {
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return &models.SubscriptionValidationResponse{
				Valid:          true,
				FeatureEnabled: false,
				QuotaAvailable: true,
			}, nil
		}

		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "SMS",
			Recipient: "+1234567890",
		}

		_, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err == nil {
			t.Fatalf("Expected error for feature disabled, got none")
		}

		if apiError, ok := err.(*models.APIError); ok {
			if apiError.Code != models.ErrorCodeFeatureDisabled {
				t.Errorf("Expected error code %s, got %s", models.ErrorCodeFeatureDisabled, apiError.Code)
			}
		} else {
			t.Errorf("Expected APIError, got %T", err)
		}
	})

	// Test quota exceeded
	t.Run("Quota exceeded", func(t *testing.T) {
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return &models.SubscriptionValidationResponse{
				Valid:          true,
				FeatureEnabled: true,
				QuotaAvailable: false,
			}, nil
		}

		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "SMS",
			Recipient: "+1234567890",
		}

		_, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err == nil {
			t.Fatalf("Expected error for quota exceeded, got none")
		}

		if apiError, ok := err.(*models.APIError); ok {
			if apiError.Code != models.ErrorCode2FAQuotaExceeded {
				t.Errorf("Expected error code %s, got %s", models.ErrorCode2FAQuotaExceeded, apiError.Code)
			}
		} else {
			t.Errorf("Expected APIError, got %T", err)
		}
	})

	// Test invalid channel
	t.Run("Invalid channel", func(t *testing.T) {
		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "INVALID",
			Recipient: "user@example.com",
		}

		_, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err == nil {
			t.Fatalf("Expected error for invalid channel, got none")
		}

		if apiError, ok := err.(*models.APIError); ok {
			if apiError.Code != models.ErrorCodeInvalidChannel {
				t.Errorf("Expected error code %s, got %s", models.ErrorCodeInvalidChannel, apiError.Code)
			}
		} else {
			t.Errorf("Expected APIError, got %T", err)
		}
	})

	// Test subscription service error
	t.Run("Subscription service error", func(t *testing.T) {
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return nil, fmt.Errorf("subscription service unavailable")
		}

		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "EMAIL",
			Recipient: "user@example.com",
		}

		_, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err == nil {
			t.Fatalf("Expected error for subscription service failure, got none")
		}

		if apiError, ok := err.(*models.APIError); ok {
			if apiError.Code != models.ErrorCodeServiceUnavailable {
				t.Errorf("Expected error code %s, got %s", models.ErrorCodeServiceUnavailable, apiError.Code)
			}
		} else {
			t.Errorf("Expected APIError, got %T", err)
		}
	})

	// Test notification service error
	t.Run("Notification service error", func(t *testing.T) {
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return &models.SubscriptionValidationResponse{
				Valid:          true,
				FeatureEnabled: true,
				QuotaAvailable: true,
			}, nil
		}

		mockNotificationClient.SendNotificationFunc = func(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error) {
			return nil, fmt.Errorf("notification service unavailable")
		}

		req := &models.TwoFactorAuthRequest{
			UserID:    "user-123",
			ClientID:  "tenant-pro",
			Channel:   "EMAIL",
			Recipient: "user@example.com",
		}

		_, err := service.TriggerTwoFactorAuth(context.Background(), req)
		if err == nil {
			t.Fatalf("Expected error for notification service failure, got none")
		}

		if apiError, ok := err.(*models.APIError); ok {
			if apiError.Code != models.ErrorCodeServiceUnavailable {
				t.Errorf("Expected error code %s, got %s", models.ErrorCodeServiceUnavailable, apiError.Code)
			}
		} else {
			t.Errorf("Expected APIError, got %T", err)
		}
	})

	// Test different tenant configurations
	t.Run("Different tenant configurations", func(t *testing.T) {
		mockSubscriptionClient.ValidateSubscriptionFunc = func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
			return &models.SubscriptionValidationResponse{
				Valid:          true,
				FeatureEnabled: true,
				QuotaAvailable: true,
			}, nil
		}

		mockNotificationClient.SendNotificationFunc = func(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error) {
			return &models.NotificationResponse{
				Success:   true,
				MessageID: "test-message-id",
			}, nil
		}

		testCases := []struct {
			clientID       string
			expectedDigits int
		}{
			{"tenant-basic", 4},
			{"tenant-pro", 6},
			{"tenant-enterprise", 8},
			{"unknown-tenant", 6}, // default
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("Tenant %s", tc.clientID), func(t *testing.T) {
				req := &models.TwoFactorAuthRequest{
					UserID:    "user-123",
					ClientID:  tc.clientID,
					Channel:   "EMAIL",
					Recipient: "user@example.com",
				}

				resp, err := service.TriggerTwoFactorAuth(context.Background(), req)
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}

				if !resp.Success {
					t.Errorf("Expected success=true, got %v", resp.Success)
				}

				if resp.OTPDigitLength != tc.expectedDigits {
					t.Errorf("Expected OTP digit length=%d, got %d", tc.expectedDigits, resp.OTPDigitLength)
				}
			})
		}
	})
}
