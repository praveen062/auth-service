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

// TenantAuthHandler handles tenant authentication requests
type TenantAuthHandler struct {
	tenantService service.TenantService
	logger        *logger.Logger
}

// NewTenantAuthHandler creates a new tenant auth handler
func NewTenantAuthHandler(tenantService service.TenantService, logger *logger.Logger) *TenantAuthHandler {
	return &TenantAuthHandler{
		tenantService: tenantService,
		logger:        logger,
	}
}

// AuthenticateTenant handles tenant authentication
// @Summary Authenticate tenant
// @Description Authenticate a tenant using client credentials
// @Tags tenant-auth
// @Accept json
// @Produce json
// @Param request body models.TenantAuthRequest true "Tenant authentication request"
// @Success 200 {object} models.TenantAuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/tenant/auth [post]
func (h *TenantAuthHandler) AuthenticateTenant(c *gin.Context) {
	var req models.TenantAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind tenant auth request", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Validate grant type
	if req.GrantType != "client_credentials" {
		h.logger.Warn("Unsupported grant type", zap.String("grant_type", req.GrantType))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "unsupported_grant_type",
			Message: "Only client_credentials grant type is supported",
		})
		return
	}

	// Authenticate tenant
	response, err := h.tenantService.AuthenticateTenant(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Tenant authentication failed",
			zap.String("client_id", req.ClientID),
			zap.Error(err))
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "authentication_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("Tenant authenticated successfully",
		zap.String("tenant_id", response.TenantID),
		zap.String("tenant_name", response.TenantName))
	c.JSON(http.StatusOK, response)
}

// RefreshTenantToken handles tenant token refresh
// @Summary Refresh tenant token
// @Description Refresh a tenant access token using refresh token
// @Tags tenant-auth
// @Accept json
// @Produce json
// @Param request body map[string]string true "Refresh token request"
// @Success 200 {object} models.TenantAuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/tenant/refresh [post]
func (h *TenantAuthHandler) RefreshTenantToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind refresh token request", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Refresh tenant token
	response, err := h.tenantService.RefreshTenantToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.logger.Error("Tenant token refresh failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "token_refresh_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("Tenant token refreshed successfully", zap.String("tenant_id", response.TenantID))
	c.JSON(http.StatusOK, response)
}

// RevokeTenantToken handles tenant token revocation
// @Summary Revoke tenant token
// @Description Revoke a tenant access token
// @Tags tenant-auth
// @Accept json
// @Produce json
// @Param request body map[string]string true "Revoke token request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/tenant/revoke [post]
func (h *TenantAuthHandler) RevokeTenantToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind revoke token request", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Revoke tenant token
	err := h.tenantService.RevokeTenantToken(c.Request.Context(), req.Token)
	if err != nil {
		h.logger.Error("Tenant token revocation failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "token_revocation_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("Tenant token revoked successfully")
	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Token revoked successfully",
	})
}

// ValidateTenantToken validates a tenant token
// @Summary Validate tenant token
// @Description Validate a tenant access token
// @Tags tenant-auth
// @Accept json
// @Produce json
// @Param request body map[string]string true "Token validation request"
// @Success 200 {object} models.TenantToken
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/tenant/validate [post]
func (h *TenantAuthHandler) ValidateTenantToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Failed to bind token validation request", zap.Error(err))
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	// Validate tenant token
	token, err := h.tenantService.ValidateTenantToken(c.Request.Context(), req.Token)
	if err != nil {
		h.logger.Error("Tenant token validation failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "token_validation_failed",
			Message: err.Error(),
		})
		return
	}

	h.logger.Info("Tenant token validated successfully", zap.String("tenant_id", token.TenantID))
	c.JSON(http.StatusOK, token)
}

// GetTenantInfo returns information about the authenticated tenant
// @Summary Get tenant info
// @Description Get information about the authenticated tenant
// @Tags tenant-auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.Tenant
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/tenant/info [get]
func (h *TenantAuthHandler) GetTenantInfo(c *gin.Context) {
	// Get tenant from context (set by middleware)
	tenantInterface := middleware.GetTenant(c)
	if tenantInterface == nil {
		h.logger.Error("Tenant context missing")
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "tenant_context_missing",
			Message: "Tenant context is missing",
		})
		return
	}

	tenant, ok := tenantInterface.(*models.Tenant)
	if !ok {
		h.logger.Error("Invalid tenant type in context")
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "invalid_tenant_type",
			Message: "Invalid tenant type in context",
		})
		return
	}

	// Remove sensitive information
	tenant.ClientSecret = ""
	tenant.APIKey = ""
	tenant.SecretKey = ""

	h.logger.Info("Tenant info retrieved", zap.String("tenant_id", tenant.ID))
	c.JSON(http.StatusOK, tenant)
}
