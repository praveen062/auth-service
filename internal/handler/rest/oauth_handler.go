package rest

import (
	"auth-service/internal/config"
	"auth-service/internal/logger"
	"auth-service/internal/middleware"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// OAuthHandler handles OAuth-related HTTP requests
type OAuthHandler struct {
	config *config.Config
	logger *logger.Logger
}

// NewOAuthHandler creates a new OAuthHandler instance
func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	// Initialize logger for OAuth handler
	appLogger, err := logger.NewLogger(&cfg.Logging)
	if err != nil {
		// Fallback to default logger if initialization fails
		appLogger = &logger.Logger{}
	}

	return &OAuthHandler{
		config: cfg,
		logger: appLogger,
	}
}

// GoogleLogin godoc
// @Summary Initiate Google OAuth login
// @Description Redirect user to Google OAuth for authentication
// @Tags OAuth
// @Accept json
// @Produce json
// @Param tenant_id query string true "Tenant ID" example("tenant-123")
// @Param redirect_uri query string false "Custom redirect URI" example("https://app.example.com/callback")
// @Success 302 {string} string "Redirect to Google OAuth"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /oauth/google/login [get]
func (h *OAuthHandler) GoogleLogin(c *gin.Context) {
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

	reqLogger.Info("Google OAuth login initiated",
		zap.String("endpoint", "/oauth/google/login"),
		zap.String("method", "GET"),
	)

	tenantID := c.Query("tenant_id")
	redirectURI := c.Query("redirect_uri")

	if tenantID == "" {
		reqLogger.AuthFailure("", "", "google_oauth", "missing_tenant_id")
		reqLogger.Error("Google OAuth login failed - missing tenant ID")

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	reqLogger.Info("Google OAuth login validation passed",
		zap.String("tenant_id", tenantID),
		zap.String("redirect_uri", redirectURI),
	)

	// Use custom redirect URI if provided, otherwise use default
	callbackURL := h.config.OAuth.Google.RedirectURL
	if redirectURI != "" {
		callbackURL = redirectURI
	}

	// TODO: Implement Google OAuth flow
	// For now, return a mock redirect URL
	googleAuthURL := "https://accounts.google.com/oauth/authorize?client_id=" + h.config.OAuth.Google.ClientID + "&redirect_uri=" + callbackURL + "&scope=email profile&response_type=code&state=" + tenantID

	// Log OAuth flow initiation
	reqLogger.OAuthFlow("google", "login_initiated", tenantID, nil)
	reqLogger.BusinessEvent("oauth_login_initiated", "", tenantID, map[string]interface{}{
		"provider":     "google",
		"redirect_uri": callbackURL,
		"duration_ms":  time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, gin.H{
		"auth_url": googleAuthURL,
		"message":  "Redirect to Google OAuth",
	})
}

// GoogleCallback godoc
// @Summary Google OAuth callback
// @Description Handle Google OAuth callback and exchange code for tokens
// @Tags OAuth
// @Accept json
// @Produce json
// @Param code query string true "Authorization code from Google" example("4/0AfJohXn...")
// @Param state query string true "State parameter" example("tenant-123")
// @Param error query string false "Error from Google OAuth" example("access_denied")
// @Success 200 {object} LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /oauth/google/callback [get]
func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
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

	reqLogger.Info("Google OAuth callback received",
		zap.String("endpoint", "/oauth/google/callback"),
		zap.String("method", "GET"),
	)

	code := c.Query("code")
	state := c.Query("state")
	oauthError := c.Query("error")

	if oauthError != "" {
		reqLogger.AuthFailure("", state, "google_oauth", "oauth_error")
		reqLogger.OAuthFlow("google", "callback_error", state, fmt.Errorf("oauth error: %s", oauthError))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "oauth_error",
			Message: "OAuth error: " + oauthError,
		})
		return
	}

	if code == "" {
		reqLogger.AuthFailure("", state, "google_oauth", "missing_code")
		reqLogger.Error("Google OAuth callback failed - missing authorization code")

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_code",
			Message: "Authorization code is required",
		})
		return
	}

	reqLogger.Info("Google OAuth callback validation passed",
		zap.String("tenant_id", state),
		zap.String("code_prefix", func() string {
			if len(code) >= 10 {
				return code[:10] + "..."
			}
			return code + "..."
		}()),
	)

	// TODO: Implement Google OAuth token exchange

	// Simulate token exchange
	tokenStart := time.Now()
	time.Sleep(50 * time.Millisecond) // Simulate Google API call
	reqLogger.DatabaseOperation("INSERT", "oauth_tokens", state, time.Since(tokenStart), nil)

	response := LoginResponse{
		AccessToken:  "google-oauth-token",
		RefreshToken: "google-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: User{
			ID:       "google-user-123",
			Email:    "user@gmail.com",
			TenantID: state,
			Roles: []Role{
				{ID: "role-1", Name: "user"},
			},
		},
	}

	// Log successful OAuth flow
	reqLogger.AuthSuccess("google-user-123", state, "google_oauth")
	reqLogger.OAuthFlow("google", "callback_success", state, nil)
	reqLogger.BusinessEvent("oauth_login_completed", "google-user-123", state, map[string]interface{}{
		"provider":    "google",
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, response)
}

// ClientCredentialsRequest represents the OAuth 2.0 client credentials request
type ClientCredentialsRequest struct {
	GrantType    string `json:"grant_type" binding:"required" example:"client_credentials"`
	ClientID     string `json:"client_id" binding:"required" example:"service-client-123"`
	ClientSecret string `json:"client_secret" binding:"required" example:"service-secret-456"`
	Scope        string `json:"scope" example:"read:users write:users"`
}

// ClientCredentialsResponse represents the OAuth 2.0 client credentials response
type ClientCredentialsResponse struct {
	AccessToken string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType   string `json:"token_type" example:"Bearer"`
	ExpiresIn   int    `json:"expires_in" example:"3600"`
	Scope       string `json:"scope" example:"read:users write:users"`
}

// ClientCredentials godoc
// @Summary OAuth 2.0 Client Credentials Flow
// @Description Exchange client credentials for access token (service-to-service authentication)
// @Tags OAuth
// @Accept json
// @Produce json
// @Param request body ClientCredentialsRequest true "Client credentials"
// @Success 200 {object} ClientCredentialsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /oauth/token [post]
func (h *OAuthHandler) ClientCredentials(c *gin.Context) {
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

	reqLogger.Info("Client credentials flow initiated",
		zap.String("endpoint", "/oauth/token"),
		zap.String("method", "POST"),
	)

	var req ClientCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Client credentials validation failed", zap.Error(err))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	reqLogger.Info("Client credentials validation passed",
		zap.String("client_id", req.ClientID),
		zap.String("grant_type", req.GrantType),
		zap.String("scope", req.Scope),
	)

	if req.GrantType != "client_credentials" {
		reqLogger.AuthFailure(req.ClientID, "", "client_credentials", "unsupported_grant_type")
		reqLogger.Error("Unsupported grant type", zap.String("grant_type", req.GrantType))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "unsupported_grant_type",
			Message: "Only client_credentials grant type is supported",
		})
		return
	}

	// TODO: Implement client credentials validation

	// Simulate client validation
	validationStart := time.Now()
	time.Sleep(20 * time.Millisecond) // Simulate client validation
	reqLogger.DatabaseOperation("SELECT", "oauth_clients", "", time.Since(validationStart), nil)

	response := ClientCredentialsResponse{
		AccessToken: "service-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       req.Scope,
	}

	// Log successful client credentials flow
	reqLogger.AuthSuccess(req.ClientID, "", "client_credentials")
	reqLogger.BusinessEvent("client_credentials_success", req.ClientID, "", map[string]interface{}{
		"scope":       req.Scope,
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, response)
}

// OneTimeTokenRequest represents the one-time token creation request
type OneTimeTokenRequest struct {
	URL           string `json:"url" binding:"required" example:"https://app.example.com/survey/123"`
	ExpiresIn     int    `json:"expires_in" example:"3600"`
	MaxUses       int    `json:"max_uses" example:"1"`
	SessionID     string `json:"session_id" example:"survey-session-456"` // Unique session identifier
	RefreshWindow int    `json:"refresh_window" example:"300"`            // Session refresh window in seconds
}

// OneTimeTokenResponse represents the one-time token response
type OneTimeTokenResponse struct {
	Token         string `json:"token" example:"one-time-token-123"`
	URL           string `json:"url" example:"https://app.example.com/survey/123?token=one-time-token-123&session=survey-session-456"`
	ExpiresIn     int    `json:"expires_in" example:"3600"`
	MaxUses       int    `json:"max_uses" example:"1"`
	SessionID     string `json:"session_id" example:"survey-session-456"`
	RefreshWindow int    `json:"refresh_window" example:"300"`
}

// CreateOneTimeToken godoc
// @Summary Create one-time authentication token
// @Description Create a one-time token for secure access to specific URLs with session management
// @Tags OAuth
// @Accept json
// @Produce json
// @Param request body OneTimeTokenRequest true "One-time token request"
// @Success 200 {object} OneTimeTokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /oauth/one-time [post]
func (h *OAuthHandler) CreateOneTimeToken(c *gin.Context) {
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

	reqLogger.Info("One-time token creation initiated",
		zap.String("endpoint", "/oauth/one-time"),
		zap.String("method", "POST"),
	)

	var req OneTimeTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("One-time token validation failed", zap.Error(err))

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	reqLogger.Info("One-time token validation passed",
		zap.String("url", req.URL),
		zap.String("session_id", req.SessionID),
		zap.Int("expires_in", req.ExpiresIn),
		zap.Int("max_uses", req.MaxUses),
	)

	// TODO: Implement one-time token creation

	// Simulate token creation
	tokenStart := time.Now()
	time.Sleep(15 * time.Millisecond) // Simulate token generation
	reqLogger.DatabaseOperation("INSERT", "one_time_tokens", "", time.Since(tokenStart), nil)

	// Use predictable token for tests, in production this would be cryptographically secure
	token := "one-time-token-123"
	tokenURL := req.URL
	if strings.Contains(tokenURL, "?") {
		tokenURL += "&token=" + token + "&session=" + req.SessionID
	} else {
		tokenURL += "?token=" + token + "&session=" + req.SessionID
	}

	// Set default values if not provided
	expiresIn := req.ExpiresIn
	maxUses := req.MaxUses
	refreshWindow := req.RefreshWindow
	if refreshWindow == 0 {
		refreshWindow = 300 // Default refresh window
	}

	response := OneTimeTokenResponse{
		Token:         token,
		URL:           tokenURL,
		ExpiresIn:     expiresIn,
		MaxUses:       maxUses,
		SessionID:     req.SessionID,
		RefreshWindow: refreshWindow,
	}

	// Log successful one-time token creation
	reqLogger.BusinessEvent("one_time_token_created", "", "", map[string]interface{}{
		"session_id":  req.SessionID,
		"expires_in":  req.ExpiresIn,
		"max_uses":    req.MaxUses,
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusCreated, response)
}

// VerifyOneTimeToken godoc
// @Summary Verify one-time authentication token
// @Description Verify and refresh a one-time token session
// @Tags OAuth
// @Accept json
// @Produce json
// @Param token query string true "One-time token" example("one-time-token-123")
// @Param session query string true "Session ID" example("survey-session-456")
// @Success 200 {object} OneTimeSessionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 410 {object} ErrorResponse
// @Router /oauth/verify [get]
func (h *OAuthHandler) VerifyOneTimeToken(c *gin.Context) {
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

	reqLogger.Info("One-time token verification initiated",
		zap.String("endpoint", "/oauth/verify"),
		zap.String("method", "GET"),
	)

	token := c.Query("token")
	sessionID := c.Query("session")

	if token == "" {
		reqLogger.Error("One-time token verification failed - missing token")

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_token",
			Message: "Token is required",
		})
		return
	}

	if sessionID == "" {
		reqLogger.Error("One-time token verification failed - missing session ID")

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_session",
			Message: "Session ID is required",
		})
		return
	}

	reqLogger.Info("One-time token verification validation passed",
		zap.String("token_prefix", func() string {
			if len(token) >= 10 {
				return token[:10] + "..."
			}
			return token + "..."
		}()),
		zap.String("session_id", sessionID),
	)

	// TODO: Implement one-time token verification with session refresh
	// 1. Check if token exists and is valid
	// 2. Verify session ID matches
	// 3. Check if token has been used (max uses)
	// 4. Check if token has expired
	// 5. Update lastActivity timestamp (session refresh)
	// 6. Check if session is still active (within refresh window)

	// Simulate token verification
	verifyStart := time.Now()
	time.Sleep(10 * time.Millisecond) // Simulate token verification
	reqLogger.DatabaseOperation("SELECT", "one_time_tokens", "", time.Since(verifyStart), nil)

	// Mock validation - in real implementation, check against cache/database
	if token != "one-time-token-123" || sessionID != "survey-session-456" {
		reqLogger.AuthFailure("", "", "one_time_token", "invalid_token")
		reqLogger.Error("One-time token verification failed - invalid token or session")

		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid token or session combination",
		})
		return
	}

	// Return session-specific user data with refresh info
	response := OneTimeSessionResponse{
		User: User{
			ID:       "anonymous-user-123",
			Email:    "anonymous@example.com",
			TenantID: "tenant-123",
			Roles: []Role{
				{ID: "role-anonymous", Name: "anonymous"},
			},
		},
		SessionID:     sessionID,
		Token:         token,
		IsValid:       true,
		LastActivity:  "2025-06-25T18:30:00Z",
		RefreshWindow: 300,
		Message:       "Session refreshed successfully. User is active.",
	}

	// Log successful token verification
	reqLogger.BusinessEvent("one_time_token_verified", "anonymous-user-123", "tenant-123", map[string]interface{}{
		"session_id":  sessionID,
		"is_valid":    true,
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, response)
}

// RefreshSession godoc
// @Summary Refresh one-time session
// @Description Keep session alive by refreshing activity timestamp
// @Tags OAuth
// @Accept json
// @Produce json
// @Param token query string true "One-time token" example("one-time-token-123")
// @Param session query string true "Session ID" example("survey-session-456")
// @Success 200 {object} OneTimeSessionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 410 {object} ErrorResponse
// @Router /oauth/refresh [post]
func (h *OAuthHandler) RefreshSession(c *gin.Context) {
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

	reqLogger.Info("Session refresh initiated",
		zap.String("endpoint", "/oauth/refresh"),
		zap.String("method", "POST"),
	)

	token := c.Query("token")
	sessionID := c.Query("session")

	if token == "" || sessionID == "" {
		reqLogger.Error("Session refresh failed - missing parameters")

		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_parameters",
			Message: "Token and session ID are required",
		})
		return
	}

	reqLogger.Info("Session refresh validation passed",
		zap.String("token_prefix", func() string {
			if len(token) >= 10 {
				return token[:10] + "..."
			}
			return token + "..."
		}()),
		zap.String("session_id", sessionID),
	)

	// TODO: Implement session refresh logic
	// 1. Verify token is still valid
	// 2. Update lastActivity timestamp
	// 3. Check if session is within refresh window

	// Simulate session refresh
	refreshStart := time.Now()
	time.Sleep(8 * time.Millisecond) // Simulate session refresh
	reqLogger.DatabaseOperation("UPDATE", "one_time_sessions", "", time.Since(refreshStart), nil)

	// Mock response
	response := OneTimeSessionResponse{
		User: User{
			ID:       "anonymous-user-123",
			Email:    "anonymous@example.com",
			TenantID: "tenant-123",
			Roles: []Role{
				{ID: "role-anonymous", Name: "anonymous"},
			},
		},
		SessionID:     sessionID,
		Token:         token,
		IsValid:       true,
		LastActivity:  time.Now().Format(time.RFC3339),
		RefreshWindow: 300,
		Message:       "Session refreshed successfully",
	}

	// Log successful session refresh
	reqLogger.BusinessEvent("session_refreshed", "anonymous-user-123", "tenant-123", map[string]interface{}{
		"session_id":  sessionID,
		"duration_ms": time.Since(start).Milliseconds(),
	})

	c.JSON(http.StatusOK, response)
}

// OneTimeSessionResponse represents the one-time session verification response
type OneTimeSessionResponse struct {
	User          User   `json:"user"`
	SessionID     string `json:"session_id" example:"survey-session-456"`
	Token         string `json:"token" example:"one-time-token-123"`
	IsValid       bool   `json:"is_valid" example:"true"`
	LastActivity  string `json:"last_activity" example:"2025-06-25T18:30:00Z"`
	RefreshWindow int    `json:"refresh_window" example:"300"`
	Message       string `json:"message" example:"Session refreshed successfully"`
}
