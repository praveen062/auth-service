package rest

import (
	"auth-service/internal/config"
	"auth-service/internal/logger"
	"auth-service/internal/middleware"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	config *config.Config
	logger *logger.Logger
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(cfg *config.Config) *AuthHandler {
	// Initialize logger for auth handler
	appLogger, err := logger.NewLogger(&cfg.Logging)
	if err != nil {
		// Fallback to default logger if initialization fails
		appLogger = &logger.Logger{}
	}

	return &AuthHandler{
		config: cfg,
		logger: appLogger,
	}
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"password123"`
	TenantID string `json:"tenant_id" binding:"required" example:"tenant-123"`
}

// LoginResponse represents the login response body
type LoginResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int    `json:"expires_in" example:"3600"`
	User         User   `json:"user"`
}

// User represents a user in the system
type User struct {
	ID       string `json:"id" example:"user-123"`
	Email    string `json:"email" example:"user@example.com"`
	TenantID string `json:"tenant_id" example:"tenant-123"`
	Roles    []Role `json:"roles"`
}

// Role represents a user role
type Role struct {
	ID   string `json:"id" example:"role-123"`
	Name string `json:"name" example:"admin"`
}

// Login godoc
// @Summary User login
// @Description Authenticate a user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
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

	reqLogger.Info("Login attempt started",
		zap.String("endpoint", "/auth/login"),
		zap.String("method", "POST"),
	)

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.AuthFailure("", req.TenantID, "password", "validation_error")
		reqLogger.Error("Login validation failed", zap.Error(err))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	reqLogger.Info("Login validation passed",
		zap.String("email", req.Email),
		zap.String("tenant_id", req.TenantID),
	)

	// TODO: Implement actual authentication logic
	// For now, return a mock response

	// Simulate database operation
	dbStart := time.Now()
	// Mock database query
	time.Sleep(10 * time.Millisecond) // Simulate DB latency
	reqLogger.DatabaseOperation("SELECT", "users", req.TenantID, time.Since(dbStart), nil)

	// Simulate cache operation
	cacheStart := time.Now()
	// Mock cache check
	time.Sleep(5 * time.Millisecond) // Simulate cache latency
	reqLogger.CacheOperation("GET", "user_session:"+req.Email, req.TenantID, false, time.Since(cacheStart), nil)

	response := LoginResponse{
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: User{
			ID:       "user-123",
			Email:    req.Email,
			TenantID: req.TenantID,
			Roles: []Role{
				{ID: "role-1", Name: "user"},
			},
		},
	}

	// Log successful authentication
	reqLogger.AuthSuccess("user-123", req.TenantID, "password")
	reqLogger.BusinessEvent("user_login", "user-123", req.TenantID, map[string]interface{}{
		"login_method": "password",
		"roles":        []string{"user"},
		"duration_ms":  time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, response)
}

// RegisterRequest represents the registration request body
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email" example:"user@example.com"`
	Password  string `json:"password" binding:"required" example:"password123"`
	TenantID  string `json:"tenant_id" binding:"required" example:"tenant-123"`
	FirstName string `json:"first_name" binding:"required" example:"John"`
	LastName  string `json:"last_name" binding:"required" example:"Doe"`
}

// Register godoc
// @Summary User registration
// @Description Register a new user
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 201 {object} User
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
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

	reqLogger.Info("Registration attempt started",
		zap.String("endpoint", "/auth/register"),
		zap.String("method", "POST"),
	)

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Registration validation failed", zap.Error(err))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	reqLogger.Info("Registration validation passed",
		zap.String("email", req.Email),
		zap.String("tenant_id", req.TenantID),
		zap.String("first_name", req.FirstName),
		zap.String("last_name", req.LastName),
	)

	// TODO: Implement actual registration logic

	// Simulate database operations
	dbStart := time.Now()
	// Mock database queries
	time.Sleep(15 * time.Millisecond)                                                      // Simulate DB latency
	reqLogger.DatabaseOperation("SELECT", "users", req.TenantID, time.Since(dbStart), nil) // Check if user exists

	insertStart := time.Now()
	time.Sleep(20 * time.Millisecond) // Simulate DB insert
	reqLogger.DatabaseOperation("INSERT", "users", req.TenantID, time.Since(insertStart), nil)

	user := User{
		ID:       "user-123",
		Email:    req.Email,
		TenantID: req.TenantID,
		Roles: []Role{
			{ID: "role-1", Name: "user"},
		},
	}

	// Log successful registration
	reqLogger.BusinessEvent("user_registration", "user-123", req.TenantID, map[string]interface{}{
		"email":       req.Email,
		"first_name":  req.FirstName,
		"last_name":   req.LastName,
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusCreated, user)
}

// RefreshTokenRequest represents the refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Refresh an expired access token using a refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
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

	reqLogger.Info("Token refresh attempt started",
		zap.String("endpoint", "/auth/refresh"),
		zap.String("method", "POST"),
	)

	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Token refresh validation failed", zap.Error(err))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	reqLogger.Info("Token refresh validation passed",
		zap.String("refresh_token_prefix", req.RefreshToken[:10]+"..."),
	)

	// TODO: Implement actual token refresh logic

	// Simulate token validation
	tokenStart := time.Now()
	time.Sleep(5 * time.Millisecond) // Simulate token validation
	reqLogger.DatabaseOperation("SELECT", "refresh_tokens", "tenant-123", time.Since(tokenStart), nil)

	response := LoginResponse{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: User{
			ID:       "user-123",
			Email:    "user@example.com",
			TenantID: "tenant-123",
			Roles: []Role{
				{ID: "role-1", Name: "user"},
			},
		},
	}

	// Log successful token refresh
	reqLogger.BusinessEvent("token_refresh", "user-123", "tenant-123", map[string]interface{}{
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, response)
}

// Logout godoc
// @Summary User logout
// @Description Logout a user and invalidate their tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} SuccessResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
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

	reqLogger.Info("Logout attempt started",
		zap.String("endpoint", "/auth/logout"),
		zap.String("method", "POST"),
	)

	// TODO: Implement actual logout logic (invalidate tokens)

	// Simulate token invalidation
	invalidateStart := time.Now()
	time.Sleep(10 * time.Millisecond) // Simulate token invalidation
	reqLogger.DatabaseOperation("UPDATE", "refresh_tokens", "tenant-123", time.Since(invalidateStart), nil)

	// Log successful logout
	reqLogger.BusinessEvent("user_logout", "user-123", "tenant-123", map[string]interface{}{
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Successfully logged out",
	})
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error" example:"validation_error"`
	Message string `json:"message" example:"Invalid request data"`
}

// SuccessResponse represents a success response
type SuccessResponse struct {
	Message string `json:"message" example:"Operation completed successfully"`
}
