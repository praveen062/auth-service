package middleware

import (
	"auth-service/internal/models"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRBACService is a mock implementation of RBACService for testing
type MockRBACService struct {
	mock.Mock
}

func (m *MockRBACService) AssignRoleToUser(ctx context.Context, userID, roleID, tenantID string) error {
	args := m.Called(ctx, userID, roleID, tenantID)
	return args.Error(0)
}

func (m *MockRBACService) AssignRoleToService(ctx context.Context, serviceID, roleID, tenantID string) error {
	args := m.Called(ctx, serviceID, roleID, tenantID)
	return args.Error(0)
}

func (m *MockRBACService) AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}

func (m *MockRBACService) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	args := m.Called(ctx, userID, permission, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACService) ServiceHasPermission(ctx context.Context, serviceID, permission, tenantID string) (bool, error) {
	args := m.Called(ctx, serviceID, permission, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRBACService) GetUserRoles(ctx context.Context, userID, tenantID string) ([]models.Role, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Get(0).([]models.Role), args.Error(1)
}

func (m *MockRBACService) GetRolePermissions(ctx context.Context, roleID string) ([]models.Permission, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]models.Permission), args.Error(1)
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestRBACMiddleware_UserHasPermission_Success(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	// Mock the RBAC service to return true for permission check
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "read:users", "tenant-123").Return(true, nil)

	middleware := RBACMiddleware(mockRBAC, "read:users")

	// Add middleware and a handler that sets user context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	mockRBAC.AssertExpectations(t)
}

func TestRBACMiddleware_UserDoesNotHavePermission(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	// Mock the RBAC service to return false for permission check
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "write:users", "tenant-123").Return(false, nil)

	middleware := RBACMiddleware(mockRBAC, "write:users")

	// Add middleware and a handler that sets user context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "forbidden", response["error"])

	mockRBAC.AssertExpectations(t)
}

func TestRBACMiddleware_MissingUserID(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	middleware := RBACMiddleware(mockRBAC, "read:users")

	// Add middleware but only set tenant_id, missing user_id
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "missing user or tenant context", response["error"])
}

func TestRBACMiddleware_MissingTenantID(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	middleware := RBACMiddleware(mockRBAC, "read:users")

	// Add middleware but only set user_id, missing tenant_id
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "missing user or tenant context", response["error"])
}

func TestRBACMiddleware_RBACServiceError(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	// Mock the RBAC service to return an error
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "read:users", "tenant-123").Return(false, assert.AnError)

	middleware := RBACMiddleware(mockRBAC, "read:users")

	// Add middleware and a handler that sets user context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Execute
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "permission check failed", response["error"])

	mockRBAC.AssertExpectations(t)
}

func TestRBACMiddleware_DifferentPermissions(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	// Mock the RBAC service for different permissions
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "admin:users", "tenant-123").Return(true, nil)
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "delete:users", "tenant-123").Return(false, nil)

	middleware := RBACMiddleware(mockRBAC, "admin:users")

	// Add middleware and a handler that sets user context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/admin", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "admin access"})
	})

	// Test admin permission (should pass)
	req1 := httptest.NewRequest("GET", "/admin", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test delete permission (should fail)
	middleware2 := RBACMiddleware(mockRBAC, "delete:users")
	router2 := setupTestRouter()
	router2.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router2.Use(middleware2)
	router2.GET("/delete", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "delete access"})
	})

	req2 := httptest.NewRequest("GET", "/delete", nil)
	w2 := httptest.NewRecorder()
	router2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusForbidden, w2.Code)

	mockRBAC.AssertExpectations(t)
}

func TestRBACMiddleware_DifferentUsers(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	// Mock the RBAC service for different users
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "read:users", "tenant-123").Return(true, nil)
	mockRBAC.On("UserHasPermission", mock.Anything, "user-456", "read:users", "tenant-123").Return(false, nil)

	middleware := RBACMiddleware(mockRBAC, "read:users")

	// Add middleware and a handler that sets user context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test user-123 (should pass)
	req1 := httptest.NewRequest("GET", "/test", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test user-456 (should fail)
	router2 := setupTestRouter()
	router2.Use(func(c *gin.Context) {
		c.Set("user_id", "user-456")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router2.Use(middleware)
	router2.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	router2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusForbidden, w2.Code)

	mockRBAC.AssertExpectations(t)
}

func TestRBACMiddleware_DifferentTenants(t *testing.T) {
	// Setup
	router := setupTestRouter()
	mockRBAC := new(MockRBACService)

	// Mock the RBAC service for different tenants
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "read:users", "tenant-123").Return(true, nil)
	mockRBAC.On("UserHasPermission", mock.Anything, "user-123", "read:users", "tenant-456").Return(false, nil)

	middleware := RBACMiddleware(mockRBAC, "read:users")

	// Add middleware and a handler that sets user context
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-123")
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test tenant-123 (should pass)
	req1 := httptest.NewRequest("GET", "/test", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test tenant-456 (should fail)
	router2 := setupTestRouter()
	router2.Use(func(c *gin.Context) {
		c.Set("user_id", "user-123")
		c.Set("tenant_id", "tenant-456")
		c.Next()
	})
	router2.Use(middleware)
	router2.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	router2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusForbidden, w2.Code)

	mockRBAC.AssertExpectations(t)
}

// Helper function to unmarshal JSON response
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
