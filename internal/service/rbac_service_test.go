package service

import (
	"auth-service/internal/models"
	"context"
	"testing"

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

func TestRBACService_AssignRoleToUser_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return success
	mockRBAC.On("AssignRoleToUser", ctx, "user-123", "role-456", "tenant-789").Return(nil)

	// Execute
	err := mockRBAC.AssignRoleToUser(ctx, "user-123", "role-456", "tenant-789")

	// Assert
	assert.NoError(t, err)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_AssignRoleToUser_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("AssignRoleToUser", ctx, "user-123", "role-456", "tenant-789").Return(assert.AnError)

	// Execute
	err := mockRBAC.AssignRoleToUser(ctx, "user-123", "role-456", "tenant-789")

	// Assert
	assert.Error(t, err)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_AssignRoleToService_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return success
	mockRBAC.On("AssignRoleToService", ctx, "service-123", "role-456", "tenant-789").Return(nil)

	// Execute
	err := mockRBAC.AssignRoleToService(ctx, "service-123", "role-456", "tenant-789")

	// Assert
	assert.NoError(t, err)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_AssignRoleToService_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("AssignRoleToService", ctx, "service-123", "role-456", "tenant-789").Return(assert.AnError)

	// Execute
	err := mockRBAC.AssignRoleToService(ctx, "service-123", "role-456", "tenant-789")

	// Assert
	assert.Error(t, err)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_AssignPermissionToRole_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return success
	mockRBAC.On("AssignPermissionToRole", ctx, "role-456", "permission-789").Return(nil)

	// Execute
	err := mockRBAC.AssignPermissionToRole(ctx, "role-456", "permission-789")

	// Assert
	assert.NoError(t, err)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_AssignPermissionToRole_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("AssignPermissionToRole", ctx, "role-456", "permission-789").Return(assert.AnError)

	// Execute
	err := mockRBAC.AssignPermissionToRole(ctx, "role-456", "permission-789")

	// Assert
	assert.Error(t, err)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_UserHasPermission_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return true for permission check
	mockRBAC.On("UserHasPermission", ctx, "user-123", "read:users", "tenant-789").Return(true, nil)

	// Execute
	hasPermission, err := mockRBAC.UserHasPermission(ctx, "user-123", "read:users", "tenant-789")

	// Assert
	assert.NoError(t, err)
	assert.True(t, hasPermission)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_UserHasPermission_NoPermission(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return false for permission check
	mockRBAC.On("UserHasPermission", ctx, "user-123", "write:users", "tenant-789").Return(false, nil)

	// Execute
	hasPermission, err := mockRBAC.UserHasPermission(ctx, "user-123", "write:users", "tenant-789")

	// Assert
	assert.NoError(t, err)
	assert.False(t, hasPermission)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_UserHasPermission_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("UserHasPermission", ctx, "user-123", "read:users", "tenant-789").Return(false, assert.AnError)

	// Execute
	hasPermission, err := mockRBAC.UserHasPermission(ctx, "user-123", "read:users", "tenant-789")

	// Assert
	assert.Error(t, err)
	assert.False(t, hasPermission)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_ServiceHasPermission_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return true for permission check
	mockRBAC.On("ServiceHasPermission", ctx, "service-123", "read:users", "tenant-789").Return(true, nil)

	// Execute
	hasPermission, err := mockRBAC.ServiceHasPermission(ctx, "service-123", "read:users", "tenant-789")

	// Assert
	assert.NoError(t, err)
	assert.True(t, hasPermission)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_ServiceHasPermission_NoPermission(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return false for permission check
	mockRBAC.On("ServiceHasPermission", ctx, "service-123", "write:users", "tenant-789").Return(false, nil)

	// Execute
	hasPermission, err := mockRBAC.ServiceHasPermission(ctx, "service-123", "write:users", "tenant-789")

	// Assert
	assert.NoError(t, err)
	assert.False(t, hasPermission)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_ServiceHasPermission_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("ServiceHasPermission", ctx, "service-123", "read:users", "tenant-789").Return(false, assert.AnError)

	// Execute
	hasPermission, err := mockRBAC.ServiceHasPermission(ctx, "service-123", "read:users", "tenant-789")

	// Assert
	assert.Error(t, err)
	assert.False(t, hasPermission)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_GetUserRoles_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	expectedRoles := []models.Role{
		{ID: "role-1", Name: "admin", TenantID: "tenant-789", IsDefault: false},
		{ID: "role-2", Name: "user", TenantID: "tenant-789", IsDefault: true},
	}

	// Mock the service to return roles
	mockRBAC.On("GetUserRoles", ctx, "user-123", "tenant-789").Return(expectedRoles, nil)

	// Execute
	roles, err := mockRBAC.GetUserRoles(ctx, "user-123", "tenant-789")

	// Assert
	assert.NoError(t, err)
	assert.Len(t, roles, 2)
	assert.Equal(t, "role-1", roles[0].ID)
	assert.Equal(t, "admin", roles[0].Name)
	assert.Equal(t, "role-2", roles[1].ID)
	assert.Equal(t, "user", roles[1].Name)
	assert.True(t, roles[1].IsDefault)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_GetUserRoles_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("GetUserRoles", ctx, "user-123", "tenant-789").Return([]models.Role{}, assert.AnError)

	// Execute
	roles, err := mockRBAC.GetUserRoles(ctx, "user-123", "tenant-789")

	// Assert
	assert.Error(t, err)
	assert.Empty(t, roles)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_GetRolePermissions_Success(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	expectedPermissions := []models.Permission{
		{ID: "perm-1", Name: "read:users"},
		{ID: "perm-2", Name: "write:users"},
		{ID: "perm-3", Name: "delete:users"},
	}

	// Mock the service to return permissions
	mockRBAC.On("GetRolePermissions", ctx, "role-456").Return(expectedPermissions, nil)

	// Execute
	permissions, err := mockRBAC.GetRolePermissions(ctx, "role-456")

	// Assert
	assert.NoError(t, err)
	assert.Len(t, permissions, 3)
	assert.Equal(t, "perm-1", permissions[0].ID)
	assert.Equal(t, "read:users", permissions[0].Name)
	assert.Equal(t, "perm-2", permissions[1].ID)
	assert.Equal(t, "write:users", permissions[1].Name)
	assert.Equal(t, "perm-3", permissions[2].ID)
	assert.Equal(t, "delete:users", permissions[2].Name)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_GetRolePermissions_Error(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the service to return an error
	mockRBAC.On("GetRolePermissions", ctx, "role-456").Return([]models.Permission{}, assert.AnError)

	// Execute
	permissions, err := mockRBAC.GetRolePermissions(ctx, "role-456")

	// Assert
	assert.Error(t, err)
	assert.Empty(t, permissions)
	mockRBAC.AssertExpectations(t)
}

func TestRBACService_Integration_UserRoleAssignment(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the complete flow: assign role, check permission, get roles
	mockRBAC.On("AssignRoleToUser", ctx, "user-123", "admin-role", "tenant-789").Return(nil)
	mockRBAC.On("AssignPermissionToRole", ctx, "admin-role", "admin:users").Return(nil)
	mockRBAC.On("UserHasPermission", ctx, "user-123", "admin:users", "tenant-789").Return(true, nil)

	expectedRoles := []models.Role{
		{ID: "admin-role", Name: "admin", TenantID: "tenant-789", IsDefault: false},
	}
	mockRBAC.On("GetUserRoles", ctx, "user-123", "tenant-789").Return(expectedRoles, nil)

	// Execute - assign role to user
	err1 := mockRBAC.AssignRoleToUser(ctx, "user-123", "admin-role", "tenant-789")
	assert.NoError(t, err1)

	// Execute - assign permission to role
	err2 := mockRBAC.AssignPermissionToRole(ctx, "admin-role", "admin:users")
	assert.NoError(t, err2)

	// Execute - check if user has permission
	hasPermission, err3 := mockRBAC.UserHasPermission(ctx, "user-123", "admin:users", "tenant-789")
	assert.NoError(t, err3)
	assert.True(t, hasPermission)

	// Execute - get user roles
	roles, err4 := mockRBAC.GetUserRoles(ctx, "user-123", "tenant-789")
	assert.NoError(t, err4)
	assert.Len(t, roles, 1)
	assert.Equal(t, "admin-role", roles[0].ID)
	assert.Equal(t, "admin", roles[0].Name)

	mockRBAC.AssertExpectations(t)
}

func TestRBACService_Integration_ServiceRoleAssignment(t *testing.T) {
	// Setup
	mockRBAC := new(MockRBACService)
	ctx := context.Background()

	// Mock the complete flow for service role assignment
	mockRBAC.On("AssignRoleToService", ctx, "api-service", "service-role", "tenant-789").Return(nil)
	mockRBAC.On("AssignPermissionToRole", ctx, "service-role", "service:read").Return(nil)
	mockRBAC.On("ServiceHasPermission", ctx, "api-service", "service:read", "tenant-789").Return(true, nil)

	// Execute - assign role to service
	err1 := mockRBAC.AssignRoleToService(ctx, "api-service", "service-role", "tenant-789")
	assert.NoError(t, err1)

	// Execute - assign permission to role
	err2 := mockRBAC.AssignPermissionToRole(ctx, "service-role", "service:read")
	assert.NoError(t, err2)

	// Execute - check if service has permission
	hasPermission, err3 := mockRBAC.ServiceHasPermission(ctx, "api-service", "service:read", "tenant-789")
	assert.NoError(t, err3)
	assert.True(t, hasPermission)

	mockRBAC.AssertExpectations(t)
}
