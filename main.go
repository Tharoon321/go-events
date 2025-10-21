package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/Tharoon321/go-events/config"
	"github.com/Tharoon321/go-events/controllers"
	"github.com/Tharoon321/go-events/middleware"
)

func main() {
	// Load environment variables
	_ = godotenv.Load()

	// Connect to MongoDB
	config.ConnectDB()

	// Initialize Gin router
	router := gin.Default()

	// ✅ Root route for base URL (fixes 404 on http://localhost:8080)
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "🎉 Welcome to the Go Events API!",
			"routes":  []string{"/api/auth", "/api/events"},
			"docs":    "Visit /api for available endpoints",
		})
	})

	// API routes group
	api := router.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", controllers.Register)
			auth.POST("/login", controllers.Login)
			auth.POST("/forgot-password", controllers.ForgotPassword)
			auth.POST("/reset-password", controllers.ResetPassword)
		}

		events := api.Group("/events")
		{
			events.GET("", controllers.ListEvents)
			events.GET("/:id", controllers.GetEvent)
			events.POST("", middleware.Auth(), middleware.RequireRole("creator"), controllers.CreateEvent)
			events.PUT("/:id", middleware.Auth(), middleware.RequireRole("creator"), controllers.UpdateEvent)
			events.DELETE("/:id", middleware.Auth(), middleware.RequireRole("creator"), controllers.DeleteEvent)
			events.POST("/:id/register", middleware.Auth(), controllers.RegisterForEvent)
		}
	}

	// Get port from environment (default to 8080)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Start server in a goroutine for graceful shutdown
	go func() {
		log.Printf("🚀 Server started on http://localhost:%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt (Ctrl+C)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("🛑 Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Println("Server forced to shutdown:", err)
	}

	if err := config.Client.Disconnect(ctx); err != nil {
		log.Println("Error disconnecting MongoDB:", err)
	} else {
		log.Println("✅ MongoDB disconnected")
	}

	log.Println("Server exited properly ✅")
}
