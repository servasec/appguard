package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/controllers"
	"github.com/servasec/appguard/backend/middleware"
)

func RegisterUserApiKeyRoutes(router *gin.Engine) {
	r := router.Group("/api-keys", middleware.AuthRequired(), middleware.CSRFProtection())
	{
		r.POST("", controllers.CreateApiKey)
		r.GET("", controllers.ListApiKeys)
		r.DELETE("/:id", controllers.RevokeApiKey)
	}
}
