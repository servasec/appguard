package controllers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/models"
	"github.com/servasec/appguard/backend/utils"
	"gorm.io/gorm"
)

func validateManagedPermission(subject, resource, action string, allowWildcard bool) (string, uint, string, uint, error) {
	parts := strings.Split(subject, ":")
	if len(parts) != 2 || (parts[0] != "user" && parts[0] != "team") {
		return "", 0, "", 0, fmt.Errorf("subject must be a user or team id")
	}
	subjectID, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || subjectID == 0 || subjectID > uint64(^uint(0)) {
		return "", 0, "", 0, fmt.Errorf("invalid subject id")
	}
	resourceParts := strings.Split(resource, "/")
	if len(resourceParts) != 3 || resourceParts[0] != "" || (resourceParts[1] != "applications" && resourceParts[1] != "groups") {
		return "", 0, "", 0, fmt.Errorf("resource must be one application or group")
	}
	resourceID, err := strconv.ParseUint(resourceParts[2], 10, 64)
	if err != nil || resourceID == 0 || resourceID > uint64(^uint(0)) {
		return "", 0, "", 0, fmt.Errorf("invalid resource id")
	}
	if action != "read" && action != "write" && !(allowWildcard && action == "*") {
		return "", 0, "", 0, fmt.Errorf("unsupported action")
	}
	return parts[0], uint(subjectID), resourceParts[1], uint(resourceID), nil
}

func ensureManagedPermissionEntities(subjectType string, subjectID uint, resourceType string, resourceID uint) error {
	if subjectType == "user" {
		var user models.User
		if err := config.DB.First(&user, subjectID).Error; err != nil {
			return err
		}
	} else {
		var team models.Team
		if err := config.DB.First(&team, subjectID).Error; err != nil {
			return err
		}
	}
	if resourceType == "applications" {
		var app models.Application
		if err := config.DB.First(&app, resourceID).Error; err != nil {
			return err
		}
	} else {
		var group models.Group
		if err := config.DB.First(&group, resourceID).Error; err != nil {
			return err
		}
	}
	return nil
}

type PermissionPolicy struct {
	ID       int    `json:"id"`
	Subject  string `json:"subject"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// GetPermissions returns all Casbin policies (admin only)
// @Summary List permissions
// @Tags Permissions
// @Produce json
// @Param subject query string false "Filter by subject prefix"
// @Success 200 {array} PermissionPolicy "List of policies"
// @Router /admin/permissions [get]
func GetPermissions(c *gin.Context) {
	filter := c.Query("subject")

	var policies []PermissionPolicy
	allPolicies, err := config.CEF.GetPolicy()
	if err != nil {
		utils.InternalServerError(c, "failed to load permissions")
		return
	}

	for i, p := range allPolicies {
		if len(p) >= 3 {
			if filter != "" && p[0] != filter {
				continue
			}
			policies = append(policies, PermissionPolicy{
				ID:       i + 1,
				Subject:  p[0],
				Resource: p[1],
				Action:   p[2],
			})
		}
	}

	utils.OKResponse(c, policies)
}

// GrantPermission adds a Casbin policy (admin only)
// @Summary Grant permission
// @Tags Permissions
// @Accept json
// @Produce json
// @Param input body object true "Subject, resource and action"
// @Success 201 {object} gin.H "Permission granted"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 409 {object} gin.H "Permission already exists"
// @Router /admin/permissions [post]
func GrantPermission(c *gin.Context) {
	var input struct {
		Subject  string `json:"subject"`
		UserID   uint   `json:"userId"`
		Resource string `json:"resource" binding:"required"`
		Action   string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.BadRequestError(c, "Invalid input")
		return
	}

	var sub string
	if input.Subject != "" {
		sub = input.Subject
	} else if input.UserID != 0 {
		sub = fmt.Sprintf("user:%d", input.UserID)
	} else {
		utils.BadRequestError(c, "subject or userId is required")
		return
	}
	subjectType, subjectID, resourceType, resourceID, err := validateManagedPermission(sub, input.Resource, input.Action, false)
	if err != nil {
		utils.BadRequestError(c, "Only read or write access to one application or group can be granted")
		return
	}
	if err := ensureManagedPermissionEntities(subjectType, subjectID, resourceType, resourceID); errors.Is(err, gorm.ErrRecordNotFound) {
		utils.NotFoundError(c, "User, team or resource not found")
		return
	} else if err != nil {
		utils.InternalServerError(c, "failed to verify permission scope")
		return
	}

	added, err := config.CEF.AddPolicy(sub, input.Resource, input.Action)
	if err != nil {
		utils.InternalServerError(c, "failed to add permission")
		return
	}
	if !added {
		utils.ConflictError(c, "Permission already exists")
		return
	}

	if err := config.CEF.SavePolicy(); err != nil {
		_, _ = config.CEF.RemovePolicy(sub, input.Resource, input.Action)
		utils.InternalServerError(c, "failed to save policy")
		return
	}

	utils.CreatedResponse(c, gin.H{"message": "Permission granted", "subject": sub})
}

// RevokePermission removes a Casbin policy (admin only)
// @Summary Revoke permission
// @Tags Permissions
// @Accept json
// @Produce json
// @Param input body object true "Subject, resource and action"
// @Success 200 {object} gin.H "Permission revoked"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 404 {object} gin.H "Permission not found"
// @Router /admin/permissions [delete]
func RevokePermission(c *gin.Context) {
	var input struct {
		Subject  string `json:"subject"`
		UserID   uint   `json:"userId"`
		Resource string `json:"resource" binding:"required"`
		Action   string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.BadRequestError(c, "Invalid input")
		return
	}

	var sub string
	if input.Subject != "" {
		sub = input.Subject
	} else if input.UserID != 0 {
		sub = fmt.Sprintf("user:%d", input.UserID)
	} else {
		utils.BadRequestError(c, "subject or userId is required")
		return
	}
	subjectType, subjectID, resourceType, resourceID, err := validateManagedPermission(sub, input.Resource, input.Action, true)
	if err != nil {
		utils.BadRequestError(c, "Only application or group permissions can be revoked")
		return
	}
	if err := ensureManagedPermissionEntities(subjectType, subjectID, resourceType, resourceID); errors.Is(err, gorm.ErrRecordNotFound) {
		utils.NotFoundError(c, "User, team or resource not found")
		return
	} else if err != nil {
		utils.InternalServerError(c, "failed to verify permission scope")
		return
	}

	removed, err := config.CEF.RemovePolicy(sub, input.Resource, input.Action)
	if err != nil {
		utils.InternalServerError(c, "failed to remove permission")
		return
	}
	if !removed {
		utils.NotFoundError(c, "Permission not found")
		return
	}

	if err := config.CEF.SavePolicy(); err != nil {
		_, _ = config.CEF.AddPolicy(sub, input.Resource, input.Action)
		utils.InternalServerError(c, "failed to save policy")
		return
	}

	utils.OKResponse(c, gin.H{"message": "Permission revoked"})
}

// GetApplicationPermissions returns all policies for a specific application
// @Summary List application permissions
// @Tags Permissions
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {array} PermissionPolicy "Application policies"
// @Router /applications/{id}/permissions [get]
func GetApplicationPermissions(c *gin.Context) {
	appID := c.Param("id")
	resource := fmt.Sprintf("/applications/%s", appID)

	var policies []PermissionPolicy
	allPolicies, _ := config.CEF.GetPolicy()

	for i, p := range allPolicies {
		if len(p) >= 3 && p[1] == resource {
			policies = append(policies, PermissionPolicy{
				ID:       i + 1,
				Subject:  p[0],
				Resource: p[1],
				Action:   p[2],
			})
		}
	}

	utils.OKResponse(c, policies)
}

// GrantApplicationPermission grants a user or team access to an application
// @Summary Grant application permission
// @Tags Permissions
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param input body object true "Subject (user:{id} or team:{id}) and action (read|write)"
// @Success 201 {object} gin.H "Permission granted"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 404 {object} gin.H "User, team or application not found"
// @Failure 409 {object} gin.H "Permission already exists"
// @Router /applications/{id}/permissions [post]
func GrantApplicationPermission(c *gin.Context) {
	appID := c.Param("id")

	var input struct {
		Subject string `json:"subject" binding:"required"`
		Action  string `json:"action" binding:"required,oneof=read write"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.BadRequestError(c, "Invalid input: subject (user:{id} or team:{id}) and action (read|write) are required")
		return
	}

	if !strings.HasPrefix(input.Subject, "user:") && !strings.HasPrefix(input.Subject, "team:") {
		utils.BadRequestError(c, "subject must be user:{id} or team:{id}")
		return
	}

	parts := strings.SplitN(input.Subject, ":", 2)
	subID, err := strconv.Atoi(parts[1])
	if err != nil || subID <= 0 {
		utils.BadRequestError(c, "invalid subject id")
		return
	}

	if parts[0] == "user" {
		var user models.User
		if err := config.DB.First(&user, subID).Error; err != nil {
			utils.NotFoundError(c, "User not found")
			return
		}
	} else {
		var team models.Team
		if err := config.DB.First(&team, subID).Error; err != nil {
			utils.NotFoundError(c, "Team not found")
			return
		}
	}

	var app models.Application
	if err := config.DB.First(&app, appID).Error; err != nil {
		utils.NotFoundError(c, "Application not found")
		return
	}

	resource := fmt.Sprintf("/applications/%s", appID)

	added, err := config.CEF.AddPolicy(input.Subject, resource, input.Action)
	if err != nil {
		utils.InternalServerError(c, "failed to grant permission")
		return
	}
	if !added {
		utils.ConflictError(c, "Permission already exists")
		return
	}
	if err := config.CEF.SavePolicy(); err != nil {
		utils.InternalServerError(c, "failed to save policy")
		return
	}

	utils.CreatedResponse(c, gin.H{"message": "Permission granted", "subject": input.Subject})
}

// RevokeApplicationPermission revokes a user or team's access to an application
// @Summary Revoke application permission
// @Tags Permissions
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param input body object true "Subject and action"
// @Success 200 {object} gin.H "Permission revoked"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 404 {object} gin.H "Permission not found"
// @Router /applications/{id}/permissions [delete]
func RevokeApplicationPermission(c *gin.Context) {
	appID := c.Param("id")

	var input struct {
		Subject string `json:"subject" binding:"required"`
		Action  string `json:"action" binding:"required,oneof=read write"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.BadRequestError(c, "Invalid input")
		return
	}

	resource := fmt.Sprintf("/applications/%s", appID)

	removed, err := config.CEF.RemovePolicy(input.Subject, resource, input.Action)
	if err != nil {
		utils.InternalServerError(c, "failed to revoke permission")
		return
	}
	if !removed {
		utils.NotFoundError(c, "Permission not found")
		return
	}
	if err := config.CEF.SavePolicy(); err != nil {
		utils.InternalServerError(c, "failed to save policy")
		return
	}

	utils.OKResponse(c, gin.H{"message": "Permission revoked"})
}
