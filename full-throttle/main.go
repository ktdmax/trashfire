package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/fullthrottle/platform/internal/config"
	"github.com/fullthrottle/platform/internal/server"
	"github.com/fullthrottle/platform/internal/services"
)

// BUG-001: Hardcoded database credentials in source code (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const defaultDSN = "postgres://admin:Sup3rS3cret!@db.prod.internal:5432/platform?sslmode=disable"

// BUG-002: Debug mode enabled by default in production (CWE-489, CVSS 3.3, LOW, Tier 4)
var debugMode = true

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Printf("Config load failed, using defaults: %v", err)
		cfg = config.DefaultConfig()
	}

	// BUG-003: Database connection string falls back to hardcoded credentials (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN
	}

	// BUG-004: SSL mode disabled for database connection (CWE-319, CVSS 5.9, MEDIUM, Tier 3)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// BUG-005: No connection pool limits — can exhaust DB connections (CWE-770, CVSS 5.3, MEDIUM, Tier 3)
	// Missing: db.SetMaxOpenConns(), db.SetMaxIdleConns()

	dockerSvc, err := services.NewDockerService(cfg)
	if err != nil {
		log.Printf("Docker service init failed: %v", err)
	}

	k8sSvc, err := services.NewK8sService(cfg)
	if err != nil {
		log.Printf("K8s service init failed: %v", err)
	}

	srv := server.New(cfg, db, dockerSvc, k8sSvc)

	// BUG-006: Server listens on all interfaces without TLS (CWE-319, CVSS 5.3, MEDIUM, Tier 3)
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv.Router(),
		// BUG-007: No read/write timeouts — susceptible to slowloris (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
	}

	// BUG-008: Goroutine leak — no way to cancel this goroutine on shutdown (CWE-404, CVSS 3.7, BEST_PRACTICE, Tier 5)
	go func() {
		for {
			log.Println("Health check tick")
			checkHealth(db, dockerSvc, k8sSvc)
			time.Sleep(30 * time.Second)
		}
	}()

	go func() {
		log.Printf("Server starting on %s (debug=%v)", addr, debugMode)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}

func checkHealth(db *sql.DB, docker *services.DockerService, k8s *services.K8sService) {
	// BUG-009: Error from Ping not checked (CWE-252, CVSS 3.7, BEST_PRACTICE, Tier 5)
	db.Ping()

	if docker != nil {
		// BUG-010: Error not checked from docker health ping (CWE-252, CVSS 3.7, BEST_PRACTICE, Tier 5)
		docker.Ping()
	}
}
