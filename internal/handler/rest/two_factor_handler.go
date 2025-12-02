package rest

import (
	"auth-service/internal/logger"
	"auth-service/internal/middleware"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TwoFactorHandler handles 2FA-related requests
type TwoFactorHandler struct {
	otpService service.OTPService
	logger     *logger.Logger
}

// NewTwoFactorHandler creates a new 2FA handler
func NewTwoFactorHandler(otpService service.OTPService, logger *logger.Logger) *TwoFactorHandler {
	return &TwoFactorHandler{
		otpService: otpService,
		logger:     logger,
	}
}

// TriggerTwoFactorAuth handles POST /internal/2fa/send
func (h *TwoFactorHandler) TriggerTwoFactorAuth(c *gin.Context) {
	// Safely get logger from context
	var reqLogger *logger.RequestLogger
	if loggerInterface := middleware.GetLogger(c); loggerInterface != nil {
		if reqLog, ok := loggerInterface.(*logger.RequestLogger); ok {
			reqLogger = reqLog
		}
	}

	// If no logger available, create a basic one
	if reqLogger == nil {
		reqLogger = h.logger.WithRequest(c.Request)
	}

	var req models.TwoFactorAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Failed to bind 2FA request", zap.Error(err))
		apiError := models.CreateError(models.ErrorCodeInvalidRequest, err.Error())
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Validate required fields
	if req.UserID == "" || req.ClientID == "" || req.Channel == "" || req.Recipient == "" {
		reqLogger.Error("Missing required fields in 2FA request",
			zap.String("user_id", req.UserID),
			zap.String("client_id", req.ClientID),
			zap.String("channel", req.Channel),
			zap.String("recipient", req.Recipient))
		apiError := models.CreateError(models.ErrorCodeMissingFields, "user_id, client_id, channel, and recipient are required")
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Validate channel
	if req.Channel != "EMAIL" && req.Channel != "SMS" {
		reqLogger.Error("Invalid channel in 2FA request", zap.String("channel", req.Channel))
		apiError := models.CreateError(models.ErrorCodeInvalidChannel, "channel must be EMAIL or SMS")
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Log the 2FA request
	reqLogger.Info("2FA request received",
		zap.String("user_id", req.UserID),
		zap.String("client_id", req.ClientID),
		zap.String("channel", req.Channel),
		zap.String("recipient", req.Recipient))

	// Trigger 2FA
	resp, err := h.otpService.TriggerTwoFactorAuth(c.Request.Context(), &req)
	if err != nil {
		// Check if it's a structured API error
		if apiError, ok := err.(*models.APIError); ok {
			reqLogger.Error("2FA request failed",
				zap.String("error_code", string(apiError.Code)),
				zap.String("error_type", string(apiError.Type)),
				zap.String("message", apiError.Message),
				zap.String("user_id", req.UserID),
				zap.String("client_id", req.ClientID))
			c.JSON(apiError.HTTPStatus, apiError)
			return
		}

		// Handle generic errors
		reqLogger.Error("Failed to trigger 2FA",
			zap.Error(err),
			zap.String("user_id", req.UserID),
			zap.String("client_id", req.ClientID))
		apiError := models.CreateError(models.ErrorCodeInternalError, err.Error())
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Log successful 2FA trigger
	reqLogger.Info("2FA triggered successfully",
		zap.String("user_id", req.UserID),
		zap.String("client_id", req.ClientID),
		zap.String("message_id", resp.MessageID),
		zap.Int("digit_length", resp.OTPDigitLength))

	c.JSON(http.StatusOK, resp)
}

// ValidateTwoFactorAuth handles POST /internal/2fa/validate
func (h *TwoFactorHandler) ValidateTwoFactorAuth(c *gin.Context) {
	// Safely get logger from context
	var reqLogger *logger.RequestLogger
	if loggerInterface := middleware.GetLogger(c); loggerInterface != nil {
		if reqLog, ok := loggerInterface.(*logger.RequestLogger); ok {
			reqLogger = reqLog
		}
	}

	// If no logger available, create a basic one
	if reqLogger == nil {
		reqLogger = h.logger.WithRequest(c.Request)
	}

	var req models.OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Failed to bind 2FA validation request", zap.Error(err))
		apiError := models.CreateError(models.ErrorCodeInvalidRequest, err.Error())
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Validate required fields
	if req.TenantID == "" || req.Code == "" {
		reqLogger.Error("Missing required fields in 2FA validation request",
			zap.String("tenant_id", req.TenantID),
			zap.Int("code_length", len(req.Code)))
		apiError := models.CreateError(models.ErrorCodeMissingFields, "tenant_id and code are required")
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Determine field type (email or mobile)
	if req.Email == "" && req.Mobile == "" {
		reqLogger.Error("Missing recipient field in 2FA validation request")
		apiError := models.CreateError(models.ErrorCodeMissingFields, "either email or mobile is required")
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Log the validation request
	reqLogger.Info("2FA validation request received",
		zap.String("tenant_id", req.TenantID),
		zap.String("email", req.Email),
		zap.String("mobile", req.Mobile),
		zap.Int("code_length", len(req.Code)))

	// Validate OTP
	valid, err := h.otpService.ValidateOTP(&req)
	if err != nil {
		reqLogger.Error("Failed to validate 2FA",
			zap.Error(err),
			zap.String("tenant_id", req.TenantID))
		apiError := models.CreateError(models.ErrorCodeInternalError, err.Error())
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	if valid {
		reqLogger.Info("2FA validation successful",
			zap.String("tenant_id", req.TenantID),
			zap.String("email", req.Email),
			zap.String("mobile", req.Mobile))
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "2FA validation successful",
		})
	} else {
		reqLogger.Warn("2FA validation failed",
			zap.String("tenant_id", req.TenantID),
			zap.String("email", req.Email),
			zap.String("mobile", req.Mobile))
		apiError := models.CreateError(models.ErrorCodeInvalidOTP, "Invalid or expired OTP")
		c.JSON(apiError.HTTPStatus, apiError)
	}
}

// GetTwoFactorStatus handles GET /internal/2fa/status/:client_id
func (h *TwoFactorHandler) GetTwoFactorStatus(c *gin.Context) {
	// Safely get logger from context
	var reqLogger *logger.RequestLogger
	if loggerInterface := middleware.GetLogger(c); loggerInterface != nil {
		if reqLog, ok := loggerInterface.(*logger.RequestLogger); ok {
			reqLogger = reqLog
		}
	}

	// If no logger available, create a basic one
	if reqLogger == nil {
		reqLogger = h.logger.WithRequest(c.Request)
	}

	clientID := c.Param("client_id")
	if clientID == "" {
		reqLogger.Error("Missing client_id in 2FA status request")
		apiError := models.CreateError(models.ErrorCodeMissingFields, "client_id is required")
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Get tenant config
	config, err := h.otpService.GetTenantOTPConfig(clientID)
	if err != nil {
		reqLogger.Error("Failed to get tenant config for 2FA status",
			zap.Error(err),
			zap.String("client_id", clientID))
		apiError := models.CreateError(models.ErrorCodeInternalError, err.Error())
		c.JSON(apiError.HTTPStatus, apiError)
		return
	}

	// Get SMS usage info if SMS is enabled
	var smsUsageInfo *models.SMSUsageInfo
	if config.EnableSMSOTP {
		smsUsageInfo, err = h.otpService.GetSMSUsageInfo(clientID)
		if err != nil {
			reqLogger.Error("Failed to get SMS usage info",
				zap.Error(err),
				zap.String("client_id", clientID))
		}
	}

	reqLogger.Info("2FA status retrieved",
		zap.String("client_id", clientID),
		zap.Bool("email_enabled", config.EnableEmailOTP),
		zap.Bool("sms_enabled", config.EnableSMSOTP))

	c.JSON(http.StatusOK, gin.H{
		"client_id":           clientID,
		"email_enabled":       config.EnableEmailOTP,
		"sms_enabled":         config.EnableSMSOTP,
		"otp_digit_length":    config.OTPDigitLength,
		"expiration_minutes":  config.OTPExpirationMinutes,
		"max_attempts":        config.MaxOTPAttempts,
		"rate_limit_per_hour": config.RateLimitPerHour,
		"sms_usage_info":      smsUsageInfo,
	})
}

// RegisterTwoFactorRoutes registers 2FA routes
func (h *TwoFactorHandler) RegisterTwoFactorRoutes(router *gin.RouterGroup) {
	// Internal 2FA endpoints
	internal := router.Group("/internal/2fa")
	{
		internal.POST("/send", h.TriggerTwoFactorAuth)
		internal.POST("/validate", h.ValidateTwoFactorAuth)
		internal.GET("/status/:client_id", h.GetTwoFactorStatus)
	}
}
