package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
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

func runServer() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	// Initialize logger
	log, err := logger.New(cfg.Logger)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %v", err)
	}
	slog.SetDefault(log)
	log.Info("logger initialized")

	// Initialize database connection using registry
	log.Info("initializing database connection")
	database, err := db.CreateDatabase(
		cfg.Database.Type,
		cfg.Database.URI,
		cfg.Database.MaxConns,
		int64(cfg.Database.ConnMaxLifetime),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize database connection: %v", err)
	}

	// Test database connection
	if err := database.TestConnection(context.Background()); err != nil {
		return fmt.Errorf("failed to test database connection: %v", err)
	}
	log.Info("database connection established successfully")

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
		log.Info("starting HTTP server", "addr", cfg.Server.Addr, "port", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info("received shutdown signal, starting graceful shutdown")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully close database connection
	log.Info("closing database connection")
	database.Close()

	// Attempt graceful shutdown of HTTP server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown error: %v", err)
	}

	log.Info("server shutdown completed successfully")

	return nil
}

func serverCMD(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("server cmd got unexpected arguments: %v", fs.Args())
	}

	return runServer()
}

func runToken(fileName string) error {
	// Generate new ed25519 key pair and return in PKCS#8 format
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal pkix public key error: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal pkcs8 private key error: %w", err)
	}

	publicPemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})
	if publicPemBytes == nil {
		return fmt.Errorf("encode public pem: empty result error")
	}

	privatePemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateDER,
	})
	if privatePemBytes == nil {
		return fmt.Errorf("encode private pem: empty result error")
	}

	// Return Base64 encoded private key if no output file name is provided
	if fileName == "" {
		fmt.Printf("PUBLIC_KEY=%s\n", base64.StdEncoding.EncodeToString(publicPemBytes))
		fmt.Printf("PRIVATE_KEY=%s\n", base64.StdEncoding.EncodeToString(privatePemBytes))
		return nil
	}

	if err := os.WriteFile(fileName+".pub", publicPemBytes, 0o644); err != nil {
		return fmt.Errorf("write public key to file error: %w", err)
	}

	if err := os.WriteFile(fileName+".pem", privatePemBytes, 0o600); err != nil {
		return fmt.Errorf("write private key to file error: %w", err)
	}

	fmt.Printf("key pair written to %s.pub and %s.pem\n", fileName, fileName)

	return nil
}

func tokenCMD(args []string) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var fileName string
	fs.StringVar(&fileName, "file-name", "", "file name without extension to save key pair")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("token cmd got unexpected arguments: %v", fs.Args())
	}

	return runToken(fileName)
}

func usageCMD(w *os.File) {
	fmt.Fprintln(w, "Use one of command: server, token")
}

func run(args []string) error {
	if len(args) == 0 {
		usageCMD(os.Stderr)
		return flag.ErrHelp
	}

	switch args[0] {
	case "server":
		return serverCMD(args[1:])
	case "token":
		return tokenCMD(args[1:])
	case "-h", "--help", "help":
		usageCMD(os.Stdout)
		return nil
	default:
		usageCMD(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
