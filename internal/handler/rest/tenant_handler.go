package rest

import (
	"auth-service/internal/config"
	"auth-service/internal/logger"
	"auth-service/internal/middleware"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TenantHandler handles tenant-related HTTP requests
type TenantHandler struct {
	tenantService service.TenantService
	logger        *logger.Logger
	otpService    service.OTPService
}

// NewTenantHandler creates a new TenantHandler instance
func NewTenantHandler(tenantService service.TenantService, cfg *config.Config, otpService service.OTPService) *TenantHandler {
	// Initialize logger for tenant handler
	appLogger, err := logger.NewLogger(&cfg.Logging)
	if err != nil {
		// Fallback to default logger if initialization fails
		appLogger = &logger.Logger{}
	}

	return &TenantHandler{
		tenantService: tenantService,
		logger:        appLogger,
		otpService:    otpService,
	}
}

// Note: Using CreateTenantRequest from models package

// UpdateTenantRequest represents the tenant update request
type UpdateTenantRequest struct {
	Name   string `json:"name" example:"Acme Corporation"`
	Domain string `json:"domain" example:"acme.com"`
	Plan   string `json:"plan" example:"enterprise"`
	Status string `json:"status" example:"active"` // active, suspended, inactive
}

// TenantResponse represents the tenant response
type TenantResponse struct {
	ID        string     `json:"id" example:"tenant-123"`
	Name      string     `json:"name" example:"Acme Corporation"`
	Domain    string     `json:"domain" example:"acme.com"`
	Status    string     `json:"status" example:"active"`
	Plan      string     `json:"plan" example:"pro"`
	MaxUsers  int        `json:"max_users" example:"1000"`
	Features  []string   `json:"features" example:"oauth,mfa,audit"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// TenantStatsResponse represents tenant statistics response
type TenantStatsResponse struct {
	TenantID    string    `json:"tenant_id" example:"tenant-123"`
	TotalUsers  int       `json:"total_users" example:"150"`
	ActiveUsers int       `json:"active_users" example:"120"`
	TotalLogins int       `json:"total_logins" example:"1250"`
	LastLoginAt time.Time `json:"last_login_at"`
	StorageUsed int64     `json:"storage_used" example:"52428800"` // in bytes
	APIRequests int       `json:"api_requests" example:"5000"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateTenant godoc
// @Summary Create a new tenant
// @Description Create a new client organization for the SaaS auth service
// @Tags Tenants
// @Accept json
// @Produce json
// @Param request body models.CreateTenantRequest true "Tenant creation data"
// @Success 201 {object} TenantResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tenants [post]
func (h *TenantHandler) CreateTenant(c *gin.Context) {
	start := time.Now()

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

	reqLogger.Info("Tenant creation initiated",
		zap.String("endpoint", "/tenants"),
		zap.String("method", "POST"),
	)

	var req models.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Tenant creation validation failed", zap.Error(err))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	// Validate required fields
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "MISSING_FIELDS",
			Message: "Tenant name is required",
		})
		return
	}

	// Validate OTP configuration if provided
	if req.OTPConfig != nil {
		if err := h.otpService.ValidateTenantOnboardingConfig(req.OTPConfig); err != nil {
			// Check if it's a structured API error
			if apiError, ok := err.(*models.APIError); ok {
				c.JSON(apiError.HTTPStatus, ErrorResponse{
					Error:   string(apiError.Code),
					Message: apiError.Message,
				})
			} else {
				c.JSON(http.StatusBadRequest, ErrorResponse{
					Error:   "INVALID_OTP_CONFIG",
					Message: err.Error(),
				})
			}
			return
		}
	}

	reqLogger.Info("Tenant creation validation passed",
		zap.String("name", req.Name),
		zap.String("domain", req.Domain),
		zap.String("plan", req.Plan),
	)

	// Create tenant model
	tenant := &models.Tenant{
		ID:     "tenant-" + strconv.FormatInt(time.Now().Unix(), 10), // Simple ID generation
		Name:   req.Name,
		Domain: req.Domain,
		Plan:   req.Plan,
	}

	// Create tenant
	if err := h.tenantService.CreateTenant(c.Request.Context(), tenant); err != nil {
		reqLogger.Error("Tenant creation failed", zap.Error(err))

		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "creation_failed",
			Message: "Failed to create tenant: " + err.Error(),
		})
		return
	}

	// Convert to response
	response := TenantResponse{
		ID:        tenant.ID,
		Name:      tenant.Name,
		Domain:    tenant.Domain,
		Status:    tenant.Status,
		Plan:      tenant.Plan,
		MaxUsers:  tenant.MaxUsers,
		Features:  tenant.Features,
		CreatedAt: tenant.CreatedAt,
		UpdatedAt: tenant.UpdatedAt,
		ExpiresAt: tenant.ExpiresAt,
	}

	// Log successful tenant creation
	reqLogger.BusinessEvent("tenant_created", "", tenant.ID, map[string]interface{}{
		"name":        req.Name,
		"domain":      req.Domain,
		"plan":        req.Plan,
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusCreated, response)
}

// GetTenant godoc
// @Summary Get tenant information
// @Description Retrieve tenant information by ID
// @Tags Tenants
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID" example("tenant-123")
// @Success 200 {object} TenantResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tenants/{tenant_id} [get]
func (h *TenantHandler) GetTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	// Get tenant
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "tenant_not_found",
			Message: "Tenant not found",
		})
		return
	}

	// Convert to response
	response := TenantResponse{
		ID:        tenant.ID,
		Name:      tenant.Name,
		Domain:    tenant.Domain,
		Status:    tenant.Status,
		Plan:      tenant.Plan,
		MaxUsers:  tenant.MaxUsers,
		Features:  tenant.Features,
		CreatedAt: tenant.CreatedAt,
		UpdatedAt: tenant.UpdatedAt,
		ExpiresAt: tenant.ExpiresAt,
	}

	c.JSON(http.StatusOK, response)
}

// UpdateTenant godoc
// @Summary Update tenant information
// @Description Update tenant information and settings
// @Tags Tenants
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID" example("tenant-123")
// @Param request body UpdateTenantRequest true "Tenant update data"
// @Success 200 {object} TenantResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tenants/{tenant_id} [put]
func (h *TenantHandler) UpdateTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	var req UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	// Get existing tenant
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "tenant_not_found",
			Message: "Tenant not found",
		})
		return
	}

	// Update fields
	if req.Name != "" {
		tenant.Name = req.Name
	}
	if req.Domain != "" {
		tenant.Domain = req.Domain
	}
	if req.Plan != "" {
		tenant.Plan = req.Plan
	}
	if req.Status != "" {
		tenant.Status = req.Status
	}

	// Update tenant
	if err := h.tenantService.UpdateTenant(c.Request.Context(), tenant); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "update_failed",
			Message: "Failed to update tenant: " + err.Error(),
		})
		return
	}

	// Convert to response
	response := TenantResponse{
		ID:        tenant.ID,
		Name:      tenant.Name,
		Domain:    tenant.Domain,
		Status:    tenant.Status,
		Plan:      tenant.Plan,
		MaxUsers:  tenant.MaxUsers,
		Features:  tenant.Features,
		CreatedAt: tenant.CreatedAt,
		UpdatedAt: tenant.UpdatedAt,
		ExpiresAt: tenant.ExpiresAt,
	}

	c.JSON(http.StatusOK, response)
}

// DeleteTenant godoc
// @Summary Delete tenant
// @Description Delete a tenant and all associated data
// @Tags Tenants
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID" example("tenant-123")
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tenants/{tenant_id} [delete]
func (h *TenantHandler) DeleteTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	// Delete tenant
	if err := h.tenantService.DeleteTenant(c.Request.Context(), tenantID); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "delete_failed",
			Message: "Failed to delete tenant: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Tenant deleted successfully",
	})
}

// ListTenants godoc
// @Summary List tenants
// @Description Retrieve a list of tenants with pagination
// @Tags Tenants
// @Accept json
// @Produce json
// @Param limit query int false "Number of tenants to return" example(10)
// @Param offset query int false "Number of tenants to skip" example(0)
// @Success 200 {array} TenantResponse
// @Failure 500 {object} ErrorResponse
// @Router /tenants [get]
func (h *TenantHandler) ListTenants(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Validate pagination parameters
	if limit < 1 || limit > 100 {
		limit = 10
	}
	if offset < 0 {
		offset = 0
	}

	// Get tenants
	tenants, err := h.tenantService.ListTenants(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "list_failed",
			Message: "Failed to list tenants: " + err.Error(),
		})
		return
	}

	// Convert to response
	var response []TenantResponse
	for _, tenant := range tenants {
		response = append(response, TenantResponse{
			ID:        tenant.ID,
			Name:      tenant.Name,
			Domain:    tenant.Domain,
			Status:    tenant.Status,
			Plan:      tenant.Plan,
			MaxUsers:  tenant.MaxUsers,
			Features:  tenant.Features,
			CreatedAt: tenant.CreatedAt,
			UpdatedAt: tenant.UpdatedAt,
			ExpiresAt: tenant.ExpiresAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

// GetTenantStats godoc
// @Summary Get tenant statistics
// @Description Retrieve usage statistics for a tenant
// @Tags Tenants
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID" example("tenant-123")
// @Success 200 {object} TenantStatsResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /tenants/{tenant_id}/stats [get]
func (h *TenantHandler) GetTenantStats(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	// Get tenant stats
	stats, err := h.tenantService.GetTenantStats(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "stats_not_found",
			Message: "Tenant statistics not found",
		})
		return
	}

	// Convert to response
	response := TenantStatsResponse{
		TenantID:    stats.TenantID,
		TotalUsers:  stats.TotalUsers,
		ActiveUsers: stats.ActiveUsers,
		TotalLogins: stats.TotalLogins,
		LastLoginAt: stats.LastLoginAt,
		StorageUsed: stats.StorageUsed,
		APIRequests: stats.APIRequests,
		UpdatedAt:   stats.UpdatedAt,
	}

	c.JSON(http.StatusOK, response)
}
