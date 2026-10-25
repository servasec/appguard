package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/controllers"
	"github.com/servasec/appguard/backend/middleware"
)

func RegisterDashboardRoutes(router *gin.Engine) {
	dashboard := router.Group("/dashboard", middleware.AuthRequired())
	{
		dashboard.GET("/stats", middleware.CheckPolicy("/dashboard", "read"), controllers.GetDashboardStats)
	}
}
