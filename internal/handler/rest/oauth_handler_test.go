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
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
}

// TestOAuthHandler_CreateOneTimeToken_WithAllFields tests CreateOneTimeToken with all optional fields
func TestOAuthHandler_CreateOneTimeToken_WithAllFields(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/one-time", handler.CreateOneTimeToken)

	// Execute
	requestBody := OneTimeTokenRequest{
		URL:           "https://app.example.com/survey/123",
		ExpiresIn:     7200,
		MaxUses:       5,
		SessionID:     "survey-session-456",
		RefreshWindow: 600,
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/one-time", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusCreated, w.Code)

	var response OneTimeTokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.Token)
	assert.Contains(t, response.URL, "https://app.example.com/survey/123")
	assert.Contains(t, response.URL, "token=one-time-token-123")
	assert.Contains(t, response.URL, "session=survey-session-456")
	assert.Equal(t, 7200, response.ExpiresIn)
	assert.Equal(t, 5, response.MaxUses)
	assert.Equal(t, "survey-session-456", response.SessionID)
	assert.Equal(t, 600, response.RefreshWindow)
}

// TestOAuthHandler_CreateOneTimeToken_WithDefaultValues tests CreateOneTimeToken with default values
func TestOAuthHandler_CreateOneTimeToken_WithDefaultValues(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/one-time", handler.CreateOneTimeToken)

	// Execute
	requestBody := OneTimeTokenRequest{
		URL:       "https://app.example.com/survey/123",
		SessionID: "survey-session-456", // Required field
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/one-time", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusCreated, w.Code)

	var response OneTimeTokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.Token)
	assert.Contains(t, response.URL, "https://app.example.com/survey/123")
	assert.Equal(t, 0, response.ExpiresIn)       // Default value
	assert.Equal(t, 0, response.MaxUses)         // Default value
	assert.Equal(t, 300, response.RefreshWindow) // Default value
}

// TestOAuthHandler_CreateOneTimeToken_WithInvalidJSON tests CreateOneTimeToken with invalid JSON
func TestOAuthHandler_CreateOneTimeToken_WithInvalidJSON(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/one-time", handler.CreateOneTimeToken)

	// Execute
	req := httptest.NewRequest("POST", "/one-time", bytes.NewBufferString(`{"url": "https://app.example.com/survey/123"`))
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

// TestOAuthHandler_CreateOneTimeToken_WithEmptyBody tests CreateOneTimeToken with empty body
func TestOAuthHandler_CreateOneTimeToken_WithEmptyBody(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/one-time", handler.CreateOneTimeToken)

	// Execute
	req := httptest.NewRequest("POST", "/one-time", bytes.NewBufferString(""))
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

// TestOAuthHandler_VerifyOneTimeToken_WithAllFields tests VerifyOneTimeToken with all fields
func TestOAuthHandler_VerifyOneTimeToken_WithAllFields(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/verify", handler.VerifyOneTimeToken)

	// Execute - use the exact token and session ID that the mock implementation expects
	req := httptest.NewRequest("GET", "/verify?token=one-time-token-123&session=survey-session-456", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response OneTimeSessionResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.Token)
	assert.Equal(t, "survey-session-456", response.SessionID)
	assert.True(t, response.IsValid)
	assert.NotEmpty(t, response.LastActivity)
	assert.Equal(t, 300, response.RefreshWindow)
	assert.NotEmpty(t, response.Message)
	assert.NotNil(t, response.User)
}

// TestOAuthHandler_VerifyOneTimeToken_WithMissingSessionID tests VerifyOneTimeToken with missing session ID
func TestOAuthHandler_VerifyOneTimeToken_WithMissingSessionID(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/verify", handler.VerifyOneTimeToken)

	// Execute
	req := httptest.NewRequest("GET", "/verify?token=test-token-123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_session", response.Error)
	assert.Equal(t, "Session ID is required", response.Message)
}

// TestOAuthHandler_VerifyOneTimeToken_WithInvalidToken tests VerifyOneTimeToken with invalid token
func TestOAuthHandler_VerifyOneTimeToken_WithInvalidToken(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/verify", handler.VerifyOneTimeToken)

	// Execute - use invalid token/session combination
	req := httptest.NewRequest("GET", "/verify?token=invalid-token&session=invalid-session", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "invalid_token", response.Error)
	assert.Contains(t, response.Message, "Invalid token or session combination")
}

// TestOAuthHandler_RefreshSession_WithAllFields tests RefreshSession with all fields
func TestOAuthHandler_RefreshSession_WithAllFields(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshSession)

	// Execute - use the exact token and session ID that the mock implementation expects
	req := httptest.NewRequest("POST", "/refresh?token=one-time-token-123&session=survey-session-456", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response OneTimeSessionResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.Token)
	assert.Equal(t, "survey-session-456", response.SessionID)
	assert.True(t, response.IsValid)
	assert.NotEmpty(t, response.LastActivity)
	assert.Equal(t, 300, response.RefreshWindow)
	assert.NotEmpty(t, response.Message)
	assert.NotNil(t, response.User)
}

// TestOAuthHandler_RefreshSession_WithInvalidJSON tests RefreshSession with invalid JSON
func TestOAuthHandler_RefreshSession_WithInvalidJSON(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshSession)

	// Execute - RefreshSession uses query parameters, not JSON body
	req := httptest.NewRequest("POST", "/refresh", bytes.NewBufferString(`{"session_id": "test-session-456"`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_parameters", response.Error)
}

// TestOAuthHandler_RefreshSession_WithEmptyBody tests RefreshSession with empty body
func TestOAuthHandler_RefreshSession_WithEmptyBody(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshSession)

	// Execute - RefreshSession uses query parameters, not JSON body
	req := httptest.NewRequest("POST", "/refresh", bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "missing_parameters", response.Error)
}

// TestOAuthHandler_ClientCredentials_WithScope tests ClientCredentials with scope
func TestOAuthHandler_ClientCredentials_WithScope(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/token", handler.ClientCredentials)

	// Execute
	requestBody := ClientCredentialsRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Scope:        "read:users write:users",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(body))
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
	assert.Equal(t, "read:users write:users", response.Scope)
}

// TestOAuthHandler_ClientCredentials_WithoutScope tests ClientCredentials without scope
func TestOAuthHandler_ClientCredentials_WithoutScope(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/token", handler.ClientCredentials)

	// Execute
	requestBody := ClientCredentialsRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(body))
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
	assert.Empty(t, response.Scope)
}

// TestOAuthHandler_ClientCredentials_WithEmptyScope tests ClientCredentials with empty scope
func TestOAuthHandler_ClientCredentials_WithEmptyScope(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.POST("/token", handler.ClientCredentials)

	// Execute
	requestBody := ClientCredentialsRequest{
		GrantType:    "client_credentials",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Scope:        "",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(body))
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
	assert.Empty(t, response.Scope)
}

// TestOAuthHandler_GoogleLogin_WithEmptyRedirectURI tests GoogleLogin with empty redirect URI
func TestOAuthHandler_GoogleLogin_WithEmptyRedirectURI(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/login", handler.GoogleLogin)

	// Execute
	req := httptest.NewRequest("GET", "/google/login?tenant_id=tenant-123&redirect_uri=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "auth_url")
	assert.Contains(t, response["auth_url"], "accounts.google.com")
	assert.Contains(t, response["auth_url"], "test-client-id")
}

// TestOAuthHandler_GoogleCallback_WithEmptyState tests GoogleCallback with empty state
func TestOAuthHandler_GoogleCallback_WithEmptyState(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/callback", handler.GoogleCallback)

	// Execute
	req := httptest.NewRequest("GET", "/google/callback?code=test-auth-code&state=", nil)
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
	assert.Empty(t, response.User.TenantID) // State was empty
}

// TestOAuthHandler_GoogleCallback_WithOnlyCode tests GoogleCallback with only code parameter
func TestOAuthHandler_GoogleCallback_WithOnlyCode(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/callback", handler.GoogleCallback)

	// Execute
	req := httptest.NewRequest("GET", "/google/callback?code=test-auth-code", nil)
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
}

// TestOAuthHandler_GoogleCallback_WithOnlyError tests GoogleCallback with only error parameter
func TestOAuthHandler_GoogleCallback_WithOnlyError(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	router.GET("/google/callback", handler.GoogleCallback)

	// Execute
	req := httptest.NewRequest("GET", "/google/callback?error=access_denied", nil)
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

// TestOAuthHandler_Integration tests integration of multiple OAuth endpoints
func TestOAuthHandler_Integration(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestOAuthConfig()
	handler := NewOAuthHandler(cfg)

	// Register all OAuth endpoints
	router.GET("/google/login", handler.GoogleLogin)
	router.GET("/google/callback", handler.GoogleCallback)
	router.POST("/token", handler.ClientCredentials)
	router.POST("/one-time", handler.CreateOneTimeToken)
	router.GET("/verify", handler.VerifyOneTimeToken)
	router.POST("/refresh", handler.RefreshSession)

	// Test Google Login
	t.Run("GoogleLogin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/google/login?tenant_id=tenant-123", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Test Google Callback
	t.Run("GoogleCallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/google/callback?code=test-code&state=tenant-123", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Test Client Credentials
	t.Run("ClientCredentials", func(t *testing.T) {
		requestBody := ClientCredentialsRequest{
			GrantType:    "client_credentials",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}
		body, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Test One-Time Token Creation
	t.Run("CreateOneTimeToken", func(t *testing.T) {
		requestBody := OneTimeTokenRequest{
			URL:       "https://app.example.com/survey/123",
			SessionID: "survey-session-456", // Required field
		}
		body, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/one-time", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	// Test One-Time Token Verification
	t.Run("VerifyOneTimeToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/verify?token=one-time-token-123&session=survey-session-456", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Test Session Refresh
	t.Run("RefreshSession", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/refresh?token=one-time-token-123&session=survey-session-456", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
