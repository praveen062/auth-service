package service

import (
	"auth-service/internal/models"
	"context"
)

type RBACService interface {
	AssignRoleToUser(ctx context.Context, userID, roleID, tenantID string) error
	AssignRoleToService(ctx context.Context, serviceID, roleID, tenantID string) error
	AssignPermissionToRole(ctx context.Context, roleID, permissionID string) error
	UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error)
	ServiceHasPermission(ctx context.Context, serviceID, permission, tenantID string) (bool, error)
	GetUserRoles(ctx context.Context, userID, tenantID string) ([]models.Role, error)
	GetRolePermissions(ctx context.Context, roleID string) ([]models.Permission, error)
}

// Implementation would use repositories for DB access and cache for performance.
