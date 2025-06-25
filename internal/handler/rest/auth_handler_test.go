package rest

import (
	"auth-service/internal/config"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func setupTestConfig() *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			Secret:                 "test-secret",
			ExpirationHours:        24,
			RefreshExpirationHours: 168,
			Issuer:                 "test-issuer",
			Audience:               "test-audience",
		},
		Security: config.SecurityConfig{
			BcryptCost:             12,
			PasswordMinLength:      8,
			PasswordRequireUpper:   true,
			PasswordRequireLower:   true,
			PasswordRequireNumbers: true,
			PasswordRequireSpecial: true,
		},
	}
}

func TestAuthHandler_Login_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/login", handler.Login)

	// Test data
	loginReq := LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
		TenantID: "tenant-123",
	}

	reqBody, _ := json.Marshal(loginReq)

	// Execute
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
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
	assert.Equal(t, loginReq.Email, response.User.Email)
	assert.Equal(t, loginReq.TenantID, response.User.TenantID)
	assert.Len(t, response.User.Roles, 1)
}

func TestAuthHandler_Login_InvalidEmail(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/login", handler.Login)

	// Test data
	loginReq := LoginRequest{
		Email:    "invalid-email",
		Password: "password123",
		TenantID: "tenant-123",
	}

	reqBody, _ := json.Marshal(loginReq)

	// Execute
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "validation_error", response.Error)
	assert.Contains(t, response.Message, "email")
}

func TestAuthHandler_Login_MissingFields(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/login", handler.Login)

	// Test data - missing required fields
	loginReq := map[string]interface{}{
		"email": "test@example.com",
		// missing password and tenant_id
	}

	reqBody, _ := json.Marshal(loginReq)

	// Execute
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
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

func TestAuthHandler_Register_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/register", handler.Register)

	// Test data
	registerReq := RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "password123",
		TenantID:  "tenant-123",
		FirstName: "John",
		LastName:  "Doe",
	}

	reqBody, _ := json.Marshal(registerReq)

	// Execute
	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusCreated, w.Code)

	var response User
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response.ID)
	assert.Equal(t, registerReq.Email, response.Email)
	assert.Equal(t, registerReq.TenantID, response.TenantID)
	assert.Len(t, response.Roles, 1)
}

func TestAuthHandler_Register_InvalidEmail(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/register", handler.Register)

	// Test data
	registerReq := RegisterRequest{
		Email:     "invalid-email",
		Password:  "password123",
		TenantID:  "tenant-123",
		FirstName: "John",
		LastName:  "Doe",
	}

	reqBody, _ := json.Marshal(registerReq)

	// Execute
	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "validation_error", response.Error)
	assert.Contains(t, response.Message, "email")
}

func TestAuthHandler_Register_MissingFields(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/register", handler.Register)

	// Test data - missing required fields
	registerReq := map[string]interface{}{
		"email": "test@example.com",
		// missing other required fields
	}

	reqBody, _ := json.Marshal(registerReq)

	// Execute
	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
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

func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshToken)

	// Test data
	refreshReq := RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	reqBody, _ := json.Marshal(refreshReq)

	// Execute
	req := httptest.NewRequest("POST", "/refresh", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
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

func TestAuthHandler_RefreshToken_MissingToken(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/refresh", handler.RefreshToken)

	// Test data - missing refresh token
	refreshReq := map[string]interface{}{
		// missing refresh_token
	}

	reqBody, _ := json.Marshal(refreshReq)

	// Execute
	req := httptest.NewRequest("POST", "/refresh", bytes.NewBuffer(reqBody))
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

func TestAuthHandler_Logout_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/logout", handler.Logout)

	// Execute
	req := httptest.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response SuccessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Successfully logged out", response.Message)
}

func TestAuthHandler_Login_InvalidJSON(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/login", handler.Login)

	// Test data - invalid JSON
	reqBody := []byte(`{"email": "test@example.com", "password": "password123", "tenant_id": "tenant-123"`)

	// Execute
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
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

func TestAuthHandler_Register_EmptyPassword(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := setupTestConfig()
	handler := NewAuthHandler(cfg)

	router.POST("/register", handler.Register)

	// Test data
	registerReq := RegisterRequest{
		Email:     "test@example.com",
		Password:  "",
		TenantID:  "tenant-123",
		FirstName: "John",
		LastName:  "Doe",
	}

	reqBody, _ := json.Marshal(registerReq)

	// Execute
	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
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

func TestAuthHandler_NewAuthHandler(t *testing.T) {
	// Setup
	cfg := setupTestConfig()

	// Execute
	handler := NewAuthHandler(cfg)

	// Assert
	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
}
