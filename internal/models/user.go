package models

// User represents a user in the system
type User struct {
	ID       string `json:"id" example:"user-123"`
	Email    string `json:"email" example:"user@example.com"`
	TenantID string `json:"tenant_id" example:"tenant-123"`
	Roles    []Role `json:"roles"`
}
