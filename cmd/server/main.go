package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"auth-service/internal/actuator"
	"auth-service/internal/config"
	rest "auth-service/internal/handler/rest"
	"auth-service/internal/middleware"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	// Swagger documentation
	_ "auth-service/docs"
)

// @title           Multi-Tenant OAuth Service API
// @version         1.0
// @description     A comprehensive OAuth 2.0 service with multi-tenancy, Google OAuth, and service-to-service authentication.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @securityDefinitions.oauth2.application OAuth2ClientCredentials
// @tokenUrl /api/v1/oauth/token
// @scope.read "Read access"
// @scope.write "Write access"
// @scope.admin "Admin access"

// @tag.name Authentication
// @tag.description Authentication and authorization endpoints

// @tag.name OAuth
// @tag.description OAuth 2.0 flow endpoints

// @tag.name Tenants
// @tag.description Multi-tenant management endpoints

// @tag.name RBAC
// @tag.description Role-based access control endpoints

// @tag.name Services
// @tag.description Service-to-service authentication endpoints

// ipAllowlistMiddleware allows only requests from allowed IPs
func ipAllowlistMiddleware(allowedIPs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		for _, ip := range allowedIPs {
			if strings.HasPrefix(clientIP, ip) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden: internal access only"})
	}
}

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	fmt.Printf("Loaded config: %+v\n", cfg.Server)

	// Create actuator
	appInfo := &actuator.AppInfo{
		Name:        "auth-service",
		Version:     "1.0.0",
		Description: "Multi-Tenant OAuth Service",
		BuildTime:   "2024-01-01T00:00:00Z",
		GitCommit:   "development",
		Environment: "development",
		Properties: map[string]string{
			"server.port":   fmt.Sprintf("%d", cfg.Server.Port),
			"database.host": cfg.Database.Host,
			"redis.host":    cfg.Redis.Host,
		},
	}

	act := actuator.NewActuator(appInfo)

	// Register health checks
	act.RegisterHealthCheck("memory", actuator.MemoryHealthCheck(90))
	act.RegisterHealthCheck("goroutines", actuator.GoroutineHealthCheck(1000))
	act.RegisterHealthCheck("disk", actuator.DiskSpaceHealthCheck(1))

	// Register readiness checks (these would be added when DB/Redis are connected)
	// act.RegisterReadinessCheck("database", actuator.DatabaseHealthCheck(db))
	// act.RegisterReadinessCheck("redis", actuator.RedisHealthCheck(redisClient))

	// Set up Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Register actuator routes
	act.RegisterRoutes(r)

	// Add actuator middleware for metrics tracking
	r.Use(middleware.ActuatorMiddleware(act))

	// Register REST handlers
	authHandler := rest.NewAuthHandler(cfg)
	oauthHandler := rest.NewOAuthHandler(cfg)

	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		auth.POST("/login", authHandler.Login)
		auth.POST("/register", authHandler.Register)
		auth.POST("/refresh", authHandler.RefreshToken)
		auth.POST("/logout", authHandler.Logout)

		oauth := api.Group("/oauth")
		oauth.GET("/google/login", oauthHandler.GoogleLogin)
		oauth.GET("/google/callback", oauthHandler.GoogleCallback)
		oauth.POST("/token", oauthHandler.ClientCredentials)
		oauth.POST("/one-time", oauthHandler.CreateOneTimeToken)
		oauth.GET("/verify", oauthHandler.VerifyOneTimeToken)
		oauth.POST("/refresh", oauthHandler.RefreshSession)
	}

	// Swagger UI - internal only (localhost)
	allowedIPs := []string{"127.0.0.1", "::1"}
	r.GET("/swagger/*any", ipAllowlistMiddleware(allowedIPs), ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("Starting server on %s\n", addr)
	fmt.Printf("Actuator endpoints available at:\n")
	fmt.Printf("  Health: http://%s/actuator/health\n", addr)
	fmt.Printf("  Metrics: http://%s/actuator/metrics\n", addr)
	fmt.Printf("  Prometheus: http://%s/actuator/prometheus\n", addr)
	fmt.Printf("  Info: http://%s/actuator/info\n", addr)

	if err := r.Run(addr); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
