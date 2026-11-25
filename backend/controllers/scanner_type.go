package controllers

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/models"
	"github.com/servasec/appguard/backend/utils"
)

// GetScannerTypes returns all scanner types, optionally filtered by enabled status
// @Summary List scanner types
// @Tags Scanner Types
// @Produce json
// @Param enabled query string false "Filter by enabled status (true)"
// @Success 200 {array} models.ScannerType "List of scanner types"
// @Router /scanner-types [get]
func GetScannerTypes(c *gin.Context) {
	var scannerTypes []models.ScannerType
	q := config.DB.Order("name ASC")
	if c.Query("enabled") == "true" {
		q = q.Where("enabled = ?", true)
	}
	if err := q.Find(&scannerTypes).Error; err != nil {
		utils.InternalServerError(c, "failed to fetch scanner types")
		return
	}
	for i := range scannerTypes {
		scannerTypes[i].Category, scannerTypes[i].Formats = scannerCapabilities(scannerTypes[i])
	}
	utils.OKResponse(c, scannerTypes)
}

func scannerCapabilities(scannerType models.ScannerType) (string, []string) {
	name := strings.ToLower(scannerType.Name)
	category := "SAST"
	switch name {
	case "trivy", "grype", "snyk", "osv-scanner", "npm-audit", "pip-audit", "govulncheck":
		category = "SCA"
	case "gitleaks", "trufflehog", "detect-secrets":
		category = "Secrets"
	case "checkov", "tfsec", "terrascan":
		category = "IaC"
	case "nuclei":
		category = "DAST"
	case "kubescape", "kube-bench", "docker-bench-security", "kube-linter":
		category = "Cloud & containers"
	case "sarif":
		category = "Generic"
	}

	if name == "sarif" {
		return category, []string{"SARIF"}
	}
	formats := []string{"JSON"}
	if strings.Contains(strings.ToLower(scannerType.Description), "sarif") {
		formats = append(formats, "SARIF")
	}
	if name == "nuclei" {
		formats = []string{"JSON", "JSONL"}
	}
	return category, formats
}

// UpdateScannerType enables or disables a scanner type (admin only)
// @Summary Update scanner type
// @Tags Scanner Types
// @Accept json
// @Produce json
// @Param id path string true "Scanner type ID"
// @Param input body object true "enabled field"
// @Success 200 {object} models.ScannerType "Updated scanner type"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 404 {object} gin.H "Scanner type not found"
// @Router /admin/scanner-types/{id} [put]
func UpdateScannerType(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.BadRequestError(c, "invalid scanner type id")
		return
	}

	var scannerType models.ScannerType
	if err := config.DB.First(&scannerType, id).Error; err != nil {
		utils.NotFoundError(c, "scanner type not found")
		return
	}

	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.BadRequestError(c, "invalid request body")
		return
	}
	if body.Enabled == nil {
		utils.BadRequestError(c, "enabled field is required")
		return
	}

	scannerType.Enabled = *body.Enabled
	if err := config.DB.Save(&scannerType).Error; err != nil {
		utils.InternalServerError(c, "failed to update scanner type")
		return
	}

	utils.OKResponse(c, scannerType)
}
