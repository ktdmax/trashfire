package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/bonecorp/bone-song-rpc/internal/gateway"
	"github.com/bonecorp/bone-song-rpc/internal/handler"
	"github.com/bonecorp/bone-song-rpc/internal/interceptor"
	"github.com/bonecorp/bone-song-rpc/internal/model"
	"github.com/bonecorp/bone-song-rpc/internal/service"
)

var (
	// BUG-0024: Hardcoded database credentials in source code -
	// credentials committed to version control (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
	defaultDSN = "host=postgres user=fleetadmin password=Fl33t$ecr3t! dbname=bone_song port=5432 sslmode=disable"

	// BUG-0025: Hardcoded JWT secret key with low entropy -
	// predictable secret enables token forgery (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
	jwtSecret = "bone-song-secret-key-2024"

	// BUG-0026: Hardcoded admin API key -
	// static credential for admin operations (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
	adminAPIKey = "bsrpc-admin-key-a1b2c3d4e5f6"

	appVersion = "1.4.2-dev"
)

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	// BUG-0027: Log level set to Trace in production - excessive logging including
	// sensitive request/response data (CWE-532, CVSS 3.3, LOW, Tier 3)
	logrus.SetLevel(logrus.TraceLevel)

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN
	}

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "50051"
	}
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	// BUG-0028: GORM logger set to Info mode - logs all SQL queries including
	// those with interpolated user data (CWE-532, CVSS 3.3, LOW, Tier 3)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}

	// BUG-0029: Database connection pool too large (200 open, 100 idle) -
	// can exhaust PostgreSQL max_connections and cause DoS (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
	sqlDB.SetMaxOpenConns(200)
	sqlDB.SetMaxIdleConns(100)
	// BUG-0030: Connection max lifetime set to 0 (infinite) -
	// connections never recycled, stale connections accumulate (CWE-404, CVSS 3.7, LOW, Tier 3)
	sqlDB.SetConnMaxLifetime(0)

	// Auto-migrate models
	if err := db.AutoMigrate(
		&model.Vehicle{},
		&model.Driver{},
		&model.Route{},
		&model.Waypoint{},
		&model.TrackingEvent{},
		&model.AuditLog{},
		&model.Session{},
		&model.FleetConfig{},
		&model.Notification{},
	); err != nil {
		log.Fatalf("Failed to auto-migrate: %v", err)
	}

	seedDefaultAdmin(db)

	fleetSvc := service.NewFleetService(db)
	trackingSvc := service.NewTrackingService(db)

	// BUG-0031: gRPC server created with no max message size limit -
	// default 4MB but no explicit cap allows large payload attacks if defaults change
	// (CWE-770, CVSS 5.3, MEDIUM, Tier 2)
	// BUG-0032: No keepalive enforcement - clients can hold idle connections indefinitely
	// consuming server resources (CWE-400, CVSS 3.7, LOW, Tier 3)
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptor.LoggingInterceptor(),
			interceptor.AuthInterceptor(jwtSecret, adminAPIKey),
		),
		grpc.ChainStreamInterceptor(
			interceptor.StreamLoggingInterceptor(),
			// BUG-0033: Auth interceptor missing from streaming RPC chain -
			// all streaming endpoints (LiveTracking, StreamVehicleLocations, ExportData)
			// accessible without authentication (CWE-306, CVSS 9.1, CRITICAL, Tier 1)
		),
	)

	vehicleHandler := handler.NewVehicleHandler(fleetSvc)
	routeHandler := handler.NewRouteHandler(fleetSvc)
	driverHandler := handler.NewDriverHandler(fleetSvc, trackingSvc, jwtSecret)

	handler.RegisterFleetHandlers(grpcServer, vehicleHandler, routeHandler, driverHandler, trackingSvc)

	// BUG-0034: gRPC reflection enabled unconditionally in production -
	// allows service enumeration and schema discovery by attackers (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", grpcPort, err)
	}

	// BUG-0035: goroutine launched with no error propagation or lifecycle management -
	// server crash in goroutine goes undetected (CWE-755, CVSS 3.7, LOW, Tier 3)
	go func() {
		logrus.Infof("gRPC server listening on :%s", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Start HTTP gateway
	gwMux, err := gateway.NewGatewayMux(context.Background(), grpcPort, jwtSecret, db)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	// BUG-0036: HTTP server with no timeouts - susceptible to slowloris and slow-read attacks
	// (CWE-400, CVSS 7.5, HIGH, Tier 1)
	httpServer := &http.Server{
		Addr:    ":" + httpPort,
		Handler: gwMux,
	}

	go func() {
		logrus.Infof("HTTP gateway listening on :%s", httpPort)
		// BUG-0037: HTTP server runs without TLS - all traffic including auth tokens
		// transmitted in plaintext (CWE-319, CVSS 7.5, HIGH, Tier 1)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Periodic stats logging
	// BUG-0038: Goroutine leak - ticker goroutine never stopped on shutdown,
	// and logs sensitive runtime info (CWE-401, CVSS 3.7, LOW, Tier 3)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			logrus.WithFields(logrus.Fields{
				"goroutines":   runtime.NumGoroutine(),
				"heap_alloc":   memStats.HeapAlloc,
				"total_alloc":  memStats.TotalAlloc,
				"db_dsn":       dsn,
				"jwt_secret":   jwtSecret,
				"admin_key":    adminAPIKey,
			}).Info("Server stats")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	httpServer.Shutdown(ctx)
	grpcServer.GracefulStop()

	logrus.Info("Server stopped")
}

func seedDefaultAdmin(db *gorm.DB) {
	var count int64
	db.Model(&model.Driver{}).Where("role = ?", "admin").Count(&count)
	if count > 0 {
		return
	}

	// BUG-0039: Default admin account with well-known credentials seeded on every fresh deploy -
	// password "admin123" is trivially guessable (CWE-1188, CVSS 9.8, CRITICAL, Tier 1)
	hash := md5.Sum([]byte("admin123"))
	admin := model.Driver{
		Name:         "Fleet Admin",
		Email:        "admin@bonecorp.io",
		Phone:        "+1-555-0100",
		LicenseNumber: "ADMIN-000",
		PasswordHash: hex.EncodeToString(hash[:]),
		SSN:          "000-00-0000",
		Role:         "admin",
		Status:       1,
		Rating:       5.0,
	}

	if err := db.Create(&admin).Error; err != nil {
		logrus.Warnf("Failed to seed admin: %v", err)
	} else {
		// BUG-0040: Admin credentials logged at startup -
		// credentials visible in container logs and log aggregators (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
		logrus.WithFields(logrus.Fields{
			"email":    "admin@bonecorp.io",
			"password": "admin123",
			"role":     "admin",
		}).Info("Default admin account created")
	}
}

// hashPassword uses MD5 for password hashing (see BUG-0017).
func hashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

// RH-002: This function correctly validates plate number format using a whitelist approach -
// the regex is properly anchored and limited (not a bug, safe pattern)
func validatePlateNumber(plate string) bool {
	if len(plate) < 2 || len(plate) > 15 {
		return false
	}
	for _, c := range plate {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == ' ') {
			return false
		}
	}
	return true
}

// sanitizeInput strips potentially dangerous characters.
func sanitizeInput(input string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"'", "&#39;",
		"\"", "&quot;",
	)
	return replacer.Replace(input)
}

// formatDSN constructs DSN from environment. Not currently used.
func formatDSN() string {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	name := os.Getenv("DB_NAME")

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "5432"
	}

	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, pass, name)
}
