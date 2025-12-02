package models

type Role struct {
	ID        string `gorm:"primaryKey"`
	TenantID  string `gorm:"index"`
	Name      string `gorm:"index;not null"`
	IsDefault bool   `gorm:"default:false"`
}

type Permission struct {
	ID   string `gorm:"primaryKey"`
	Name string `gorm:"unique;not null"`
}

type RolePermission struct {
	RoleID       string `gorm:"primaryKey"`
	PermissionID string `gorm:"primaryKey"`
}

type UserRole struct {
	UserID   string `gorm:"primaryKey"`
	RoleID   string `gorm:"primaryKey"`
	TenantID string `gorm:"index"`
}

type ServiceRole struct {
	ServiceID string `gorm:"primaryKey"`
	RoleID    string `gorm:"primaryKey"`
	TenantID  string `gorm:"index"`
}
