package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/models"
	"github.com/servasec/appguard/backend/utils"
	"gorm.io/gorm"
)

const integrationFreshnessWindow = 30 * 24 * time.Hour

func newIntegrationToken() (string, error) {
	raw, err := utils.GenerateRandomString(32)
	if err != nil {
		return "", err
	}
	return "ig_" + raw, nil
}

func integrationID(integration *models.ScannerIntegration) *uint {
	if integration == nil {
		return nil
	}
	return &integration.ID
}

func resolveIngestIntegration(c *gin.Context, appID, scannerTypeID uint) (*models.ScannerIntegration, error) {
	if value, exists := c.Get("ingest_integration"); exists {
		integration := value.(*models.ScannerIntegration)
		if integration.ApplicationID != appID || integration.ScannerTypeID != scannerTypeID {
			return integration, fmt.Errorf("report scanner does not match this integration")
		}
		if !integration.IsActive || integration.Status == "paused" {
			return integration, fmt.Errorf("scanner integration is paused")
		}
		return integration, nil
	}
	var integration models.ScannerIntegration
	err := config.DB.Where("application_id = ? AND scanner_type_id = ?", appID, scannerTypeID).First(&integration).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	if !integration.IsActive || integration.Status == "paused" {
		return &integration, fmt.Errorf("scanner integration is paused")
	}
	return &integration, nil
}

func markIngestIntegrationError(c *gin.Context, integration *models.ScannerIntegration, message string) {
	if integration == nil {
		if value, exists := c.Get("ingest_integration"); exists {
			integration = value.(*models.ScannerIntegration)
		}
	}
	if integration == nil {
		return
	}
	now := time.Now()
	config.DB.Model(integration).Updates(map[string]any{
		"status":       "error",
		"last_seen_at": now,
		"last_error":   message,
	})
}

func updateIngestIntegration(tx *gorm.DB, integration *models.ScannerIntegration, status string, success bool, message string) error {
	if integration == nil {
		return nil
	}
	now := time.Now()
	updates := map[string]any{
		"status":       status,
		"last_seen_at": now,
		"last_error":   message,
	}
	if success {
		updates["last_success_at"] = now
	}
	return tx.Model(integration).Updates(updates).Error
}

func recordIntegrationAudit(tx *gorm.DB, c *gin.Context, integration *models.ScannerIntegration, event string) error {
	username := ""
	if user, exists := c.Get("user"); exists {
		username = user.(*models.User).Username
	}
	return tx.Create(&models.AuditLog{
		UserID:    c.GetUint("user_id"),
		Username:  username,
		Action:    c.Request.Method,
		Resource:  fmt.Sprintf("/applications/%d/integrations/%d", integration.ApplicationID, integration.ID),
		Status:    http.StatusOK,
		Details:   fmt.Sprintf("scanner_integration.%s scanner=%s", event, integration.Name),
		IP:        c.ClientIP(),
		CreatedAt: time.Now(),
	}).Error
}

func getApplicationIntegration(c *gin.Context) (*models.ScannerIntegration, bool) {
	var integration models.ScannerIntegration
	err := config.DB.Preload("ScannerType").Where("id = ? AND application_id = ?", c.Param("integrationId"), c.Param("id")).First(&integration).Error
	if err != nil {
		utils.NotFoundError(c, "scanner integration not found")
		return nil, false
	}
	return &integration, true
}

func ListScannerIntegrations(c *gin.Context) {
	var integrations []models.ScannerIntegration
	if err := config.DB.Preload("ScannerType").Where("application_id = ?", c.Param("id")).Order("created_at ASC").Find(&integrations).Error; err != nil {
		utils.InternalServerError(c, "failed to fetch scanner integrations")
		return
	}
	for i := range integrations {
		if integrations[i].Status == "connected" && integrations[i].LastSuccessAt != nil && time.Since(*integrations[i].LastSuccessAt) > integrationFreshnessWindow {
			integrations[i].Status = "stale"
		}
	}
	utils.OKResponse(c, integrations)
}

func ListAllScannerIntegrations(c *gin.Context) {
	query := config.DB.Preload("ScannerType").Preload("Application").
		Joins("JOIN applications ON applications.id = scanner_integrations.application_id").
		Joins("JOIN scanner_types ON scanner_types.id = scanner_integrations.scanner_type_id").
		Where("applications.deleted_at IS NULL")
	accessibleIDs := utils.GetAccessibleAppIDs(c)
	if accessibleIDs != nil {
		if len(accessibleIDs) == 0 {
			utils.OKResponse(c, []models.ScannerIntegration{})
			return
		}
		query = query.Where("scanner_integrations.application_id IN ?", accessibleIDs)
	}
	if applicationID := c.Query("applicationId"); applicationID != "" {
		query = query.Where("scanner_integrations.application_id = ?", applicationID)
	}
	if category := c.Query("category"); category != "" {
		query = query.Where("scanner_integrations.category = ?", category)
	}
	if scannerTypeID := c.Query("scannerTypeId"); scannerTypeID != "" {
		query = query.Where("scanner_integrations.scanner_type_id = ?", scannerTypeID)
	}
	if search := strings.TrimSpace(c.Query("q")); search != "" {
		pattern := "%" + search + "%"
		query = query.Where("(applications.name ILIKE ? OR scanner_integrations.name ILIKE ? OR scanner_types.name ILIKE ?)", pattern, pattern, pattern)
	}
	cutoff := time.Now().Add(-integrationFreshnessWindow)
	switch c.Query("status") {
	case "awaiting_report", "error", "paused":
		query = query.Where("scanner_integrations.status = ?", c.Query("status"))
	case "connected":
		query = query.Where("scanner_integrations.status = ? AND scanner_integrations.last_success_at >= ?", "connected", cutoff)
	case "stale":
		query = query.Where("scanner_integrations.status = ? AND scanner_integrations.last_success_at < ?", "connected", cutoff)
	}

	var integrations []models.ScannerIntegration
	if err := query.Order("COALESCE(scanner_integrations.last_success_at, scanner_integrations.created_at) ASC").Find(&integrations).Error; err != nil {
		utils.InternalServerError(c, "failed to fetch scanner integrations")
		return
	}
	groupIDs := make([]uint, 0, len(integrations))
	seenGroups := make(map[uint]bool)
	for i := range integrations {
		integrations[i].ApplicationName = integrations[i].Application.Name
		groupID := integrations[i].Application.GroupID
		if !seenGroups[groupID] {
			groupIDs = append(groupIDs, groupID)
			seenGroups[groupID] = true
		}
		if integrations[i].Status == "connected" && integrations[i].LastSuccessAt != nil && integrations[i].LastSuccessAt.Before(cutoff) {
			integrations[i].Status = "stale"
		}
	}
	var groups []models.Group
	if len(groupIDs) > 0 {
		config.DB.Select("id", "name").Where("id IN ?", groupIDs).Find(&groups)
	}
	groupNames := make(map[uint]string, len(groups))
	for _, group := range groups {
		groupNames[group.ID] = group.Name
	}
	for i := range integrations {
		integrations[i].GroupName = groupNames[integrations[i].Application.GroupID]
	}
	utils.OKResponse(c, integrations)
}

func CreateScannerIntegration(c *gin.Context) {
	applicationID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequestError(c, "invalid application id")
		return
	}
	var input struct {
		ScannerTypeID uint   `json:"scannerTypeId" binding:"required"`
		Name          string `json:"name" binding:"omitempty,max=100"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.BadRequestError(c, "scannerTypeId is required and name must be at most 100 characters")
		return
	}
	var scannerType models.ScannerType
	if err := config.DB.First(&scannerType, input.ScannerTypeID).Error; err != nil {
		utils.NotFoundError(c, "scanner type not found")
		return
	}
	if !scannerType.Enabled {
		utils.BadRequestError(c, "scanner type is disabled")
		return
	}
	var existing models.ScannerIntegration
	if err := config.DB.Where("application_id = ? AND scanner_type_id = ?", applicationID, scannerType.ID).First(&existing).Error; err == nil {
		utils.ConflictError(c, "an integration for this scanner already exists; reconnect it or revoke it first")
		return
	}
	category, _ := scannerCapabilities(scannerType)
	if strings.TrimSpace(input.Name) == "" {
		input.Name = scannerType.Name
	}
	token, err := newIntegrationToken()
	if err != nil {
		utils.InternalServerError(c, "failed to generate integration token")
		return
	}
	integration := models.ScannerIntegration{
		ApplicationID: uint(applicationID),
		ScannerTypeID: scannerType.ID,
		Name:          strings.TrimSpace(input.Name),
		Category:      category,
		Configuration: "{}",
		Status:        "awaiting_report",
		IsActive:      true,
		TokenHash:     utils.HashToHex(token),
		TokenPrefix:   token[:11],
	}
	if err := config.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&integration).Error; err != nil {
			return err
		}
		if err := recordIntegrationAudit(tx, c, &integration, "created"); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if config.DB.Where("application_id = ? AND scanner_type_id = ?", applicationID, scannerType.ID).First(&existing).Error == nil {
			utils.ConflictError(c, "an integration for this scanner already exists; reconnect it or revoke it first")
			return
		}
		utils.InternalServerError(c, "failed to create scanner integration")
		return
	}
	config.DB.Preload("ScannerType").First(&integration, integration.ID)
	c.JSON(http.StatusCreated, gin.H{"integration": integration, "token": token})
}

func UpdateScannerIntegration(c *gin.Context) {
	integration, ok := getApplicationIntegration(c)
	if !ok {
		return
	}
	var input struct {
		Name          *string           `json:"name" binding:"omitempty,max=100"`
		Configuration map[string]string `json:"configuration"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.BadRequestError(c, "invalid integration update")
		return
	}
	if input.Name != nil {
		if strings.TrimSpace(*input.Name) == "" {
			utils.BadRequestError(c, "name cannot be empty")
			return
		}
		integration.Name = strings.TrimSpace(*input.Name)
	}
	if input.Configuration != nil {
		for key := range input.Configuration {
			key = strings.ToLower(key)
			if strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password") || strings.Contains(key, "credential") || strings.Contains(key, "private_key") || strings.Contains(key, "api_key") || strings.Contains(key, "access_key") {
				utils.BadRequestError(c, "configuration cannot contain credentials")
				return
			}
		}
		configuration, err := json.Marshal(input.Configuration)
		if err != nil {
			utils.BadRequestError(c, "invalid integration configuration")
			return
		}
		integration.Configuration = string(configuration)
	}
	if err := config.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(integration).Error; err != nil {
			return err
		}
		return recordIntegrationAudit(tx, c, integration, "updated")
	}); err != nil {
		utils.InternalServerError(c, "failed to update scanner integration")
		return
	}
	utils.OKResponse(c, integration)
}

func setScannerIntegrationState(c *gin.Context, active bool, event, status string) {
	integration, ok := getApplicationIntegration(c)
	if !ok {
		return
	}
	integration.IsActive = active
	integration.Status = status
	if active {
		integration.LastError = ""
	}
	if err := config.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(integration).Error; err != nil {
			return err
		}
		return recordIntegrationAudit(tx, c, integration, event)
	}); err != nil {
		utils.InternalServerError(c, "failed to update scanner integration state")
		return
	}
	utils.OKResponse(c, integration)
}

func PauseScannerIntegration(c *gin.Context) {
	setScannerIntegrationState(c, false, "paused", "paused")
}

func ReconnectScannerIntegration(c *gin.Context) {
	setScannerIntegrationState(c, true, "reconnected", "awaiting_report")
}

func RotateScannerIntegrationToken(c *gin.Context) {
	integration, ok := getApplicationIntegration(c)
	if !ok {
		return
	}
	token, err := newIntegrationToken()
	if err != nil {
		utils.InternalServerError(c, "failed to generate integration token")
		return
	}
	integration.TokenHash = utils.HashToHex(token)
	integration.TokenPrefix = token[:11]
	integration.IsActive = true
	integration.Status = "awaiting_report"
	integration.LastError = ""
	if err := config.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(integration).Error; err != nil {
			return err
		}
		return recordIntegrationAudit(tx, c, integration, "token_rotated")
	}); err != nil {
		utils.InternalServerError(c, "failed to rotate integration token")
		return
	}
	utils.OKResponse(c, gin.H{"integration": integration, "token": token})
}

func RevokeScannerIntegration(c *gin.Context) {
	integration, ok := getApplicationIntegration(c)
	if !ok {
		return
	}
	integration.IsActive = false
	integration.Status = "revoked"
	if err := config.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(integration).Error; err != nil {
			return err
		}
		if err := recordIntegrationAudit(tx, c, integration, "revoked"); err != nil {
			return err
		}
		return tx.Delete(integration).Error
	}); err != nil {
		utils.InternalServerError(c, "failed to revoke scanner integration")
		return
	}
	utils.OKResponse(c, gin.H{"message": "scanner integration revoked"})
}
