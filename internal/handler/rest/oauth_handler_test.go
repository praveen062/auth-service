package rest

import (
	"auth-service/internal/config"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestOAuthConfig() *config.Config {
	return &config.Config{
		OAuth: config.OAuthConfig{
			Google: config.GoogleOAuthConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/api/v1/oauth/google/callback",
				Scopes: []string{
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				},
			},
		},
		JWT: config.JWTConfig{
			Secret:                 "test-secret",
			ExpirationHours:        24,
			RefreshExpirationHours: 168,
			Issuer:                 "test-issuer",
			Audience:               "test-audience",
		},
		OneTime: config.OneTimeConfig{
			TokenLength:     32,
			MaxUses:         1,
			ExpirationHours: 1,
			AllowedURLs: []string{
				"/api/v1/auth/verify",
				"/api/v1/oauth/callback",
			},
		},
	}
}

func TestOAuthHandler_GoogleLogin_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/login", handler.GoogleLogin)

	// Execute
	req := httptest.NewRequest("GET", "/google/login?tenant_id=tenant-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "auth_url")
	assert.Contains(t, response, "message")
	assert.Contains(t, response["auth_url"], "accounts.google.com")
	assert.Contains(t, response["auth_url"], "test-client-id")
	assert.Contains(t, response["auth_url"], "tenant-123")
}

func TestOAuthHandler_GoogleLogin_WithCustomRedirectURI(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/login", handler.GoogleLogin)

	// Execute
	req := httptest.NewRequest("GET", "/google/login?tenant_id=tenant-123&redirect_uri=https://custom.example.com/callback", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "auth_url")
	assert.Contains(t, response["auth_url"], "custom.example.com")
}

func TestOAuthHandler_GoogleLogin_MissingTenantID(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/login", handler.GoogleLogin)

	// Execute
	req := httptest.NewRequest("GET", "/google/login", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_tenant_id", response.Error)
	assert.Equal(t, "Tenant ID is required", response.Message)
}

func TestOAuthHandler_GoogleCallback_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/callback", handler.GoogleCallback)

	// Execute
	req := httptest.NewRequest("GET", "/google/callback?code=test-auth-code&state=tenant-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response LoginResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.Equal(t, "tenant-123", response.User.TenantID)
	assert.Equal(t, "user@gmail.com", response.User.Email)
}

func TestOAuthHandler_GoogleCallback_MissingCode(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/callback", handler.GoogleCallback)

	// Execute
	req := httptest.NewRequest("GET", "/google/callback?state=tenant-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_code", response.Error)
	assert.Equal(t, "Authorization code is required", response.Message)
}

func TestOAuthHandler_GoogleCallback_OAuthError(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/callback", handler.GoogleCallback)

	// Execute
	req := httptest.NewRequest("GET", "/google/callback?error=access_denied&state=tenant-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "oauth_error", response.Error)
	assert.Contains(t, response.Message, "access_denied")
}

func TestOAuthHandler_ClientCredentials_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/token", handler.ClientCredentials)

	// Test data
	credentialsReq := ClientCredentialsRequest{
		GrantType:    "client_credentials",
		ClientID:     "service-client-123",
		ClientSecret: "service-secret-456",
		Scope:        "read:users write:users",
	}

	reqBody, _ := json.Marshal(credentialsReq)

	// Execute
	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response ClientCredentialsResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.AccessToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.Equal(t, credentialsReq.Scope, response.Scope)
}

func TestOAuthHandler_ClientCredentials_UnsupportedGrantType(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/token", handler.ClientCredentials)

	// Test data
	credentialsReq := ClientCredentialsRequest{
		GrantType:    "authorization_code",
		ClientID:     "service-client-123",
		ClientSecret: "service-secret-456",
		Scope:        "read:users write:users",
	}

	reqBody, _ := json.Marshal(credentialsReq)

	// Execute
	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "unsupported_grant_type", response.Error)
	assert.Equal(t, "Only client_credentials grant type is supported", response.Message)
}

func TestOAuthHandler_ClientCredentials_InvalidJSON(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/token", handler.ClientCredentials)

	// Test data - invalid JSON
	reqBody := []byte(`{"grant_type": "client_credentials", "client_id": "service-client-123"`)

	// Execute
	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "validation_error", response.Error)
}

func TestOAuthHandler_CreateOneTimeToken_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/one-time", handler.CreateOneTimeToken)

	// Test data
	tokenReq := OneTimeTokenRequest{
		URL:           "https://app.example.com/survey/123",
		ExpiresIn:     3600,
		MaxUses:       1,
		SessionID:     "survey-session-456",
		RefreshWindow: 300,
	}

	reqBody, _ := json.Marshal(tokenReq)

	// Execute
	req := httptest.NewRequest("POST", "/one-time", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert - should return 201 Created
	assert.Equal(t, http.StatusCreated, w.Code)

	var response OneTimeTokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.Token)
	// The implementation appends token and session parameters to the URL
	expectedURL := "https://app.example.com/survey/123?token=one-time-token-123&session=survey-session-456"
	assert.Equal(t, expectedURL, response.URL)
	assert.Equal(t, tokenReq.ExpiresIn, response.ExpiresIn)
	assert.Equal(t, tokenReq.MaxUses, response.MaxUses)
	assert.Equal(t, tokenReq.SessionID, response.SessionID)
	assert.Equal(t, tokenReq.RefreshWindow, response.RefreshWindow)
	assert.Contains(t, response.URL, response.Token)
	assert.Contains(t, response.URL, response.SessionID)
}

func TestOAuthHandler_CreateOneTimeToken_MissingURL(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/one-time", handler.CreateOneTimeToken)

	// Test data - missing required URL
	tokenReq := map[string]interface{}{
		"expires_in":     3600,
		"max_uses":       1,
		"session_id":     "survey-session-456",
		"refresh_window": 300,
	}

	reqBody, _ := json.Marshal(tokenReq)

	// Execute
	req := httptest.NewRequest("POST", "/one-time", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "validation_error", response.Error)
}

func TestOAuthHandler_VerifyOneTimeToken_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/verify", handler.VerifyOneTimeToken)

	// Execute - use the expected token and session from the implementation
	req := httptest.NewRequest("GET", "/verify?token=one-time-token-123&session=survey-session-456", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response OneTimeSessionResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.IsValid)
	assert.Equal(t, "survey-session-456", response.SessionID)
	assert.NotEmpty(t, response.Token)
	assert.NotEmpty(t, response.User.ID)
	assert.NotEmpty(t, response.LastActivity)
	assert.Greater(t, response.RefreshWindow, 0)
}

func TestOAuthHandler_VerifyOneTimeToken_MissingToken(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/verify", handler.VerifyOneTimeToken)

	// Execute
	req := httptest.NewRequest("GET", "/verify?session=session-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_token", response.Error)
	assert.Equal(t, "Token is required", response.Message)
}

func TestOAuthHandler_VerifyOneTimeToken_InvalidToken(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/verify", handler.VerifyOneTimeToken)

	// Execute - use invalid token
	req := httptest.NewRequest("GET", "/verify?token=invalid-token&session=session-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert - should return 401 Unauthorized for invalid token
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "invalid_token", response.Error)
	assert.Contains(t, response.Message, "Invalid token or session combination")
}

func TestOAuthHandler_RefreshSession_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshSession)

	// Execute - use query parameters as expected by the implementation
	req := httptest.NewRequest("POST", "/refresh?token=one-time-token-123&session=survey-session-456", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response OneTimeSessionResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response.IsValid)
	assert.Equal(t, "survey-session-456", response.SessionID)
	assert.NotEmpty(t, response.Token)
	assert.NotEmpty(t, response.User.ID)
	assert.NotEmpty(t, response.LastActivity)
	assert.Contains(t, response.Message, "refreshed successfully")
}

func TestOAuthHandler_RefreshSession_MissingSessionID(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshSession)

	// Execute - missing session parameter
	req := httptest.NewRequest("POST", "/refresh?token=valid-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_parameters", response.Error)
	assert.Equal(t, "Token and session ID are required", response.Message)
}

func TestOAuthHandler_NewOAuthHandler(t *testing.T) {
	// Setup
	cfg := setupTestOAuthConfig()

	// Execute
	handler := NewOAuthHandler(cfg)

	// Assert
	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
}
