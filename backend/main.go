// @title AppGuard API
// @version 1.0
// @description appguard platform API
// @contact.name appguard support
// @contact.email contact@servasec.com
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in cookie
// @name access_token
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/debug"
	_ "github.com/servasec/appguard/backend/docs"
	"github.com/servasec/appguard/backend/features"
	"github.com/servasec/appguard/backend/middleware"
	"github.com/servasec/appguard/backend/pro"
	"github.com/servasec/appguard/backend/routes"
	"github.com/servasec/appguard/backend/utils"
	"github.com/servasec/appguard/backend/version"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func getTrustedProxies() []string {
	cidr := os.Getenv("TRUSTED_PROXIES_CIDR")
	if cidr == "" {
		cidr = "172.70.1.0/24"
	}
	return []string{cidr}
}

func main() {
	utils.ValidateSecrets()
	config.ConnectDB()
	config.InitCasbin()
	utils.StartBlacklistCleanup()

	features.Init(os.Getenv("APPGUARD_LICENSE_KEY"))
	debug.Log("Enabled features: %v", features.F.EnabledFeatures())

	pro.Risk.StartEPSSSync()

	var gReleaseMode string
	if os.Getenv("APPGUARD_DEBUG_ENABLED") == "true" {
		gReleaseMode = gin.DebugMode
	} else {
		gReleaseMode = gin.ReleaseMode
	}
	gin.SetMode(gReleaseMode)

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	middleware.InitCSRFProtection()

	router.SetTrustedProxies(getTrustedProxies())
	allowedOrigin := os.Getenv("APPGUARD_PUBLIC_URL")
	if allowedOrigin == "" {
		log.Fatal("APPGUARD_PUBLIC_URL environment variable is required but not set")
	}
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{allowedOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	router.Use(pro.Audit.Middleware())

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	router.GET("/health", func(c *gin.Context) {
		sqlDB, err := config.DB.DB()
		if err != nil || sqlDB.Ping() != nil {
			c.JSON(503, gin.H{"status": "unhealthy"})
			return
		}
		c.JSON(200, gin.H{"status": "healthy", "version": version.NormalizeVersion()})
	})

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	routes.RegisterWellKnownRoutes(router)
	routes.RegisterAuthRoutes(router)
	pro.SSO.RegisterRoutes(router)
	routes.RegisterOAuthRoutes(router)
	routes.RegisterUserRoutes(router)
	routes.RegisterDashboardRoutes(router)
	routes.RegisterGroupRoutes(router)
	routes.RegisterApplicationRoutes(router)
	routes.RegisterScanRoutes(router)
	routes.RegisterFindingRoutes(router)
	routes.RegisterTeamRoutes(router)
	routes.RegisterScannerTypeRoutes(router)
	routes.RegisterPermissionRoutes(router)
	routes.RegisterPolicyRoutes(router)
	routes.RegisterUserApiKeyRoutes(router)

	pro.Audit.RegisterRoutes(router)
	pro.MCP.RegisterRoutes(router)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	go func() {
		debug.Log("Starting server on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
