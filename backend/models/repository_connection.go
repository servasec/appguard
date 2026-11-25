package models

import (
	"time"

	"gorm.io/gorm"
)

type RepositoryOAuthState struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	UserID         uint      `gorm:"not null;index" json:"-"`
	Provider       string    `gorm:"not null;size:20" json:"-"`
	StateHash      string    `gorm:"not null;uniqueIndex;size:64" json:"-"`
	ReturnTo       string    `gorm:"size:300" json:"-"`
	InstallationID *int64    `json:"-"`
	CreatedAt      time.Time `json:"-"`
	ExpiresAt      time.Time `gorm:"not null;index" json:"-"`
}

type RepositoryConnection struct {
	ID                    uint           `gorm:"primaryKey" json:"id"`
	UserID                uint           `gorm:"not null;index" json:"userId"`
	Provider              string         `gorm:"not null;size:20;index" json:"provider"`
	ProviderAccountID     string         `gorm:"not null;size:100" json:"providerAccountId"`
	AccountName           string         `gorm:"not null;size:200" json:"accountName"`
	InstallationID        *int64         `gorm:"index" json:"installationId,omitempty"`
	ProviderBaseURL       string         `gorm:"size:300" json:"-"`
	EncryptedAccessToken  string         `gorm:"size:2000" json:"-"`
	AccessTokenIV         string         `gorm:"size:44" json:"-"`
	EncryptedRefreshToken string         `gorm:"size:2000" json:"-"`
	RefreshTokenIV        string         `gorm:"size:44" json:"-"`
	TokenExpiresAt        *time.Time     `json:"tokenExpiresAt,omitempty"`
	Status                string         `gorm:"not null;size:20;default:connected" json:"status"`
	LastWebhookAt         *time.Time     `json:"lastWebhookAt,omitempty"`
	CreatedAt             time.Time      `json:"createdAt"`
	UpdatedAt             time.Time      `json:"updatedAt"`
	DeletedAt             gorm.DeletedAt `gorm:"index" json:"-"`
}

type ApplicationRepositoryLink struct {
	ID                   uint                 `gorm:"primaryKey" json:"id"`
	ApplicationID        uint                 `gorm:"not null;uniqueIndex:idx_repo_link_app_active" json:"applicationId"`
	ConnectionID         uint                 `gorm:"not null;index" json:"connectionId"`
	Provider             string               `gorm:"not null;size:20;uniqueIndex:idx_repo_link_external_active" json:"provider"`
	ExternalRepositoryID string               `gorm:"not null;size:100;uniqueIndex:idx_repo_link_external_active" json:"externalRepositoryId"`
	RepositoryPath       string               `gorm:"not null;size:300" json:"repositoryPath"`
	RepositoryURL        string               `gorm:"not null;size:500" json:"repositoryUrl"`
	WebhookSecretHash    string               `gorm:"size:64" json:"-"`
	WebhookStatus        string               `gorm:"not null;size:20;default:awaiting_delivery" json:"webhookStatus"`
	LastWebhookAt        *time.Time           `json:"lastWebhookAt,omitempty"`
	Application          Application          `gorm:"foreignKey:ApplicationID" json:"-"`
	Connection           RepositoryConnection `gorm:"foreignKey:ConnectionID" json:"-"`
	CreatedAt            time.Time            `json:"createdAt"`
	UpdatedAt            time.Time            `json:"updatedAt"`
	DeletedAt            gorm.DeletedAt       `gorm:"index" json:"-"`
}

type RepositoryWebhookDelivery struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Provider   string    `gorm:"not null;size:20;uniqueIndex:idx_repo_webhook_delivery" json:"provider"`
	DeliveryID string    `gorm:"not null;size:120;uniqueIndex:idx_repo_webhook_delivery" json:"deliveryId"`
	Event      string    `gorm:"not null;size:60" json:"event"`
	ReceivedAt time.Time `json:"receivedAt"`
}
