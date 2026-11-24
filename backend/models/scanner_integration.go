package models

import (
	"time"

	"gorm.io/gorm"
)

type ScannerIntegration struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	ApplicationID   uint           `gorm:"not null;index" json:"applicationId"`
	ScannerTypeID   uint           `gorm:"not null;index" json:"scannerTypeId"`
	Name            string         `gorm:"not null;size:100" json:"name"`
	Category        string         `gorm:"not null;size:40" json:"category"`
	Configuration   string         `gorm:"type:jsonb;not null;default:'{}'" json:"configuration"`
	Status          string         `gorm:"not null;size:20;default:awaiting_report" json:"status"`
	IsActive        bool           `gorm:"not null;default:true" json:"isActive"`
	TokenHash       string         `gorm:"not null;uniqueIndex;size:64" json:"-"`
	TokenPrefix     string         `gorm:"not null;size:20" json:"tokenPrefix"`
	ApplicationName string         `gorm:"-" json:"applicationName,omitempty"`
	GroupName       string         `gorm:"-" json:"groupName,omitempty"`
	LastSeenAt      *time.Time     `json:"lastSeenAt,omitempty"`
	LastSuccessAt   *time.Time     `json:"lastSuccessAt,omitempty"`
	LastError       string         `gorm:"type:text" json:"lastError,omitempty"`
	ScannerType     ScannerType    `gorm:"foreignKey:ScannerTypeID" json:"scannerType"`
	Application     Application    `gorm:"foreignKey:ApplicationID" json:"-"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}
