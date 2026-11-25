package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/controllers"
	"github.com/servasec/appguard/backend/middleware"
)

func RegisterRepositoryRoutes(router *gin.Engine) {
	router.GET("/repository-connections/github/callback", controllers.GitHubRepositoryOAuthCallback)
	router.GET("/repository-connections/gitlab/callback", controllers.GitLabRepositoryOAuthCallback)
	router.POST("/webhooks/github", controllers.GitHubRepositoryWebhook)
	router.POST("/webhooks/gitlab/:id", controllers.GitLabRepositoryWebhook)

	r := router.Group("/repository-connections", middleware.AuthRequired(), middleware.CSRFProtection(), middleware.RequireHumanAuth())
	r.GET("/providers", controllers.RepositoryProviders)
	r.GET("/providers/:provider/authorize", controllers.StartRepositoryAuthorization)
	r.GET("/connections", controllers.ListRepositoryConnections)
	r.GET("/connections/:id/repositories", controllers.ListConnectedRepositories)
	r.DELETE("/connections/:id", controllers.DisconnectRepositoryConnection)

	a := router.Group("/applications", middleware.AuthRequired(), middleware.CSRFProtection(), middleware.RequireHumanAuth())
	a.GET("/:id/repository-link", middleware.CheckPolicy("/applications/*", "read"), middleware.RequireResourceAccessByParam("applications", "id", "read"), controllers.GetApplicationRepositoryLink)
	a.POST("/:id/repository-link", middleware.CheckPolicy("/applications/*", "write"), middleware.RequireResourceAccessByParam("applications", "id", "write"), controllers.CreateApplicationRepositoryLink)
	a.DELETE("/:id/repository-link", middleware.CheckPolicy("/applications/*", "write"), middleware.RequireResourceAccessByParam("applications", "id", "write"), controllers.DeleteApplicationRepositoryLink)
}
