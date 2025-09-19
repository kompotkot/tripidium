package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kompotkot/tripidium/internal/config"
	"github.com/kompotkot/tripidium/internal/logger"
	"github.com/kompotkot/tripidium/internal/server"
	"github.com/kompotkot/tripidium/pkg/db"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Logger)
	log.Info("Logger initialized")

	// Initialize database connection using registry
	log.Info("Initializing database connection")
	database, err := db.NewPsqlDB(cfg.Database.URI, cfg.Database.MaxConns, cfg.Database.ConnMaxLifetime)
	if err != nil {
		log.Error("Failed to initialize database connection", "error", err)
		os.Exit(1)
	}

	// Test database connection
	if err := database.TestConnection(context.Background()); err != nil {
		log.Error("Failed to test database connection", "error", err)
		os.Exit(1)
	}
	log.Info("Database connection established successfully")

	// Create context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create HTTP server
	newSrv := server.NewServer(server.Dependencies{
		DB:  database,
		Cfg: cfg.Server,
		Log: log,
	})
	commonHandler := newSrv.BuildCommonHandler()
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", cfg.Server.Addr, cfg.Server.Port),
		Handler: *commonHandler,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Starting HTTP server", "addr", cfg.Server.Addr, "port", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info("Received shutdown signal, starting graceful shutdown")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully close database connection
	log.Info("Closing database connection")
	database.Close()

	// Attempt graceful shutdown of HTTP server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("Server shutdown error", "error", err)
	} else {
		log.Info("Server shutdown completed successfully")
	}

	log.Info("Application shutdown complete")
}
