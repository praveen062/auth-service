package rest

import (
	"auth-service/internal/logger"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OTPHandler handles OTP-based authentication requests
type OTPHandler struct {
	otpService service.OTPService
	logger     *logger.Logger
}

func NewOTPHandler(otpService service.OTPService, logger *logger.Logger) *OTPHandler {
	return &OTPHandler{
		otpService: otpService,
		logger:     logger,
	}
}

// RequestOTP handles OTP request with flexible delivery methods
// @Summary Request OTP for authentication
// @Description Request an OTP to be sent via email, SMS, or both based on tenant configuration
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.OTPRequest true "OTP request details"
// @Success 200 {object} models.OTPResponse
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/request-otp [post]
func (h *OTPHandler) RequestOTP(c *gin.Context) {
	var req models.OTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind OTP request", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Get tenant OTP configuration
	config, err := h.otpService.GetTenantOTPConfig(req.TenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant OTP config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "config_error",
			Message: "Failed to get tenant configuration",
		})
		return
	}

	// Generate and send OTP
	response, err := h.otpService.GenerateAndSendOTP(&req, config)
	if err != nil {
		h.logger.Error("Failed to generate and send OTP", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "otp_generation_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("OTP requested successfully",
		zap.String("email", req.Email),
		zap.String("tenant_id", req.TenantID),
		zap.String("delivery_method", string(response.DeliveryMethod)))

	c.JSON(http.StatusOK, response)
}

// VerifyOTP handles OTP verification for authentication
// @Summary Verify OTP for authentication
// @Description Verify an OTP code and authenticate the user
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.OTPVerifyRequest true "OTP verification details"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/verify-otp [post]
func (h *OTPHandler) VerifyOTP(c *gin.Context) {
	var req models.OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind OTP verify request", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Validate OTP
	valid, err := h.otpService.ValidateOTP(&req)
	if err != nil {
		h.logger.Error("OTP validation error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "validation_error",
			Message: "Failed to validate OTP",
		})
		return
	}

	if !valid {
		h.logger.Warn("Invalid OTP attempt",
			zap.String("email", req.Email),
			zap.String("tenant_id", req.TenantID))
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_otp",
			Message: "Invalid or expired OTP code",
		})
		return
	}

	// TODO: In real implementation, fetch user from database
	// For demo, create a mock user
	user := &models.User{
		ID:       "user-otp-123",
		Email:    req.Email,
		TenantID: req.TenantID,
		Roles: []models.Role{
			{ID: "role-1", Name: "user"},
		},
	}

	// Generate JWT tokens (in real implementation, use proper JWT service)
	response := LoginResponse{
		AccessToken:  "otp-access-token-" + req.Email,
		RefreshToken: "otp-refresh-token-" + req.Email,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: User{
			ID:       user.ID,
			Email:    user.Email,
			TenantID: user.TenantID,
			Roles:    []Role{{ID: user.Roles[0].ID, Name: user.Roles[0].Name}},
		},
	}

	h.logger.Info("OTP verified successfully",
		zap.String("email", req.Email),
		zap.String("tenant_id", req.TenantID),
		zap.String("delivery_method", string(req.DeliveryMethod)))

	c.JSON(http.StatusOK, response)
}

// GetOTPConfig returns available OTP methods for a tenant
// @Summary Get OTP configuration for tenant
// @Description Get available OTP delivery methods and configuration for a tenant
// @Tags Authentication
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} models.TenantOTPConfig
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/otp-config/{tenant_id} [get]
func (h *OTPHandler) GetOTPConfig(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	config, err := h.otpService.GetTenantOTPConfig(tenantID)
	if err != nil {
		h.logger.Error("Failed to get OTP config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "config_error",
			Message: "Failed to get OTP configuration",
		})
		return
	}

	c.JSON(http.StatusOK, config)
}

// UpdateOTPPreference updates user's OTP delivery preference
// @Summary Update OTP delivery preference
// @Description Update user's preferred OTP delivery method
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.UserOTPPreference true "User OTP preference"
// @Success 200 {object} models.UserOTPPreference
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/otp-preference [put]
func (h *OTPHandler) UpdateOTPPreference(c *gin.Context) {
	var pref models.UserOTPPreference
	if err := c.ShouldBindJSON(&pref); err != nil {
		h.logger.Error("Failed to bind OTP preference", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Validate delivery method
	config, err := h.otpService.GetTenantOTPConfig(pref.TenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant config for preference", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "config_error",
			Message: "Failed to get tenant configuration",
		})
		return
	}

	// Check if the preferred method is enabled for the tenant
	switch pref.PreferredMethod {
	case models.OTPDeliveryEmail:
		if !config.EnableEmailOTP {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "method_not_enabled",
				Message: "Email OTP is not enabled for this tenant",
			})
			return
		}
	case models.OTPDeliverySMS:
		if !config.EnableSMSOTP {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "method_not_enabled",
				Message: "SMS OTP is not enabled for this tenant",
			})
			return
		}
	}

	// Update preference
	err = h.otpService.UpdateUserOTPPreference(&pref)
	if err != nil {
		h.logger.Error("Failed to update OTP preference", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "update_failed",
			Message: "Failed to update OTP preference",
		})
		return
	}

	h.logger.Info("OTP preference updated",
		zap.String("user_id", pref.UserID),
		zap.String("tenant_id", pref.TenantID),
		zap.String("preferred_method", string(pref.PreferredMethod)))

	c.JSON(http.StatusOK, pref)
}

// GetSMSUsageInfo returns SMS usage information for a tenant
// @Summary Get SMS usage information
// @Description Get current SMS usage, limits, and billing cycle information for a tenant
// @Tags Authentication
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} models.SMSUsageInfo
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/sms-usage/{tenant_id} [get]
func (h *OTPHandler) GetSMSUsageInfo(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	usageInfo, err := h.otpService.GetSMSUsageInfo(tenantID)
	if err != nil {
		h.logger.Error("Failed to get SMS usage info", zap.Error(err))
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "usage_info_error",
			Message: "Failed to get SMS usage information",
		})
		return
	}

	h.logger.Info("SMS usage info retrieved",
		zap.String("tenant_id", tenantID),
		zap.Int("current_usage", usageInfo.CurrentUsage),
		zap.Int("monthly_limit", usageInfo.MonthlyLimit))

	c.JSON(http.StatusOK, usageInfo)
}
