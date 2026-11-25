package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/middleware"
	"github.com/servasec/appguard/backend/oauth"
)

func RegisterOAuthRoutes(router *gin.Engine) {
	oauthGroup := router.Group("/oauth")
	{
		oauthGroup.GET("/authorize", oauth.HandleAuthorize)
		oauthGroup.POST("/authorize", oauth.HandleAuthorize)
		oauthGroup.POST("/token", middleware.RateLimit(20), oauth.HandleToken)
		oauthGroup.POST("/register", middleware.RateLimit(10), oauth.HandleRegister)
	}
}
