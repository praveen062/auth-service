package rest

import (
	"auth-service/internal/config"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// OAuthHandler handles OAuth-related HTTP requests
type OAuthHandler struct {
	config *config.Config
}

// NewOAuthHandler creates a new OAuthHandler instance
func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{
		config: cfg,
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
	tenantID := c.Query("tenant_id")
	redirectURI := c.Query("redirect_uri")

	if tenantID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_tenant_id",
			Message: "Tenant ID is required",
		})
		return
	}

	// Use custom redirect URI if provided, otherwise use default
	callbackURL := h.config.OAuth.Google.RedirectURL
	if redirectURI != "" {
		callbackURL = redirectURI
	}

	// TODO: Implement Google OAuth flow
	// For now, return a mock redirect URL
	googleAuthURL := "https://accounts.google.com/oauth/authorize?client_id=" + h.config.OAuth.Google.ClientID + "&redirect_uri=" + callbackURL + "&scope=email profile&response_type=code&state=" + tenantID

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
	code := c.Query("code")
	state := c.Query("state")
	oauthError := c.Query("error")

	if oauthError != "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "oauth_error",
			Message: "OAuth error: " + oauthError,
		})
		return
	}

	if code == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_code",
			Message: "Authorization code is required",
		})
		return
	}

	// TODO: Implement Google OAuth token exchange
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
	var req ClientCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	if req.GrantType != "client_credentials" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "unsupported_grant_type",
			Message: "Only client_credentials grant type is supported",
		})
		return
	}

	// TODO: Implement client credentials validation
	// For now, return a mock response
	response := ClientCredentialsResponse{
		AccessToken: "service-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       req.Scope,
	}

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
// @Security BearerAuth
// @Param request body OneTimeTokenRequest true "One-time token parameters"
// @Success 201 {object} OneTimeTokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /oauth/one-time [post]
func (h *OAuthHandler) CreateOneTimeToken(c *gin.Context) {
	var req OneTimeTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
		})
		return
	}

	// Validate required fields
	if req.SessionID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_session_id",
			Message: "Session ID is required for one-time tokens",
		})
		return
	}

	// Set default refresh window if not provided
	if req.RefreshWindow == 0 {
		req.RefreshWindow = 300 // 5 minutes default
	}

	// TODO: Implement one-time token creation with session management
	// Store in cache/database: token -> {sessionID, maxUses, expiresAt, lastActivity, refreshWindow}

	// Build URL with session parameter
	urlWithParams := req.URL
	if strings.Contains(urlWithParams, "?") {
		urlWithParams += "&"
	} else {
		urlWithParams += "?"
	}
	urlWithParams += fmt.Sprintf("token=one-time-token-123&session=%s", req.SessionID)

	response := OneTimeTokenResponse{
		Token:         "one-time-token-123",
		URL:           urlWithParams,
		ExpiresIn:     req.ExpiresIn,
		MaxUses:       req.MaxUses,
		SessionID:     req.SessionID,
		RefreshWindow: req.RefreshWindow,
	}

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
	token := c.Query("token")
	sessionID := c.Query("session")

	if token == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_token",
			Message: "Token is required",
		})
		return
	}

	if sessionID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_session",
			Message: "Session ID is required",
		})
		return
	}

	// TODO: Implement one-time token verification with session refresh
	// 1. Check if token exists and is valid
	// 2. Verify session ID matches
	// 3. Check if token has been used (max uses)
	// 4. Check if token has expired
	// 5. Update lastActivity timestamp (session refresh)
	// 6. Check if session is still active (within refresh window)

	// Mock validation - in real implementation, check against cache/database
	if token != "one-time-token-123" || sessionID != "survey-session-456" {
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
	token := c.Query("token")
	sessionID := c.Query("session")

	if token == "" || sessionID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_parameters",
			Message: "Token and session ID are required",
		})
		return
	}

	// TODO: Implement session refresh logic
	// 1. Verify token is still valid
	// 2. Update lastActivity timestamp
	// 3. Check if session is within refresh window
	// 4. Return updated session info

	// Mock refresh - in real implementation, update cache/database
	if token != "one-time-token-123" || sessionID != "survey-session-456" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_token",
			Message: "Invalid token or session",
		})
		return
	}

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
		LastActivity:  "2025-06-25T18:35:00Z", // Updated timestamp
		RefreshWindow: 300,
		Message:       "Session refreshed successfully. User activity extended.",
	}

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
