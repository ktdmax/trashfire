package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/bonecorp/bone-song-rpc/internal/handler"
	"github.com/bonecorp/bone-song-rpc/internal/model"
	"github.com/bonecorp/bone-song-rpc/internal/service"
)

// GatewayMux wraps the HTTP multiplexer for the REST gateway.
type GatewayMux struct {
	mux         *http.ServeMux
	fleetSvc    *service.FleetService
	trackingSvc *service.TrackingService
	jwtSecret   string
	db          *gorm.DB
	startTime   time.Time
}

// NewGatewayMux creates a new REST gateway multiplexer.
func NewGatewayMux(ctx context.Context, grpcPort string, jwtSecret string, db *gorm.DB) (http.Handler, error) {
	gw := &GatewayMux{
		mux:         http.NewServeMux(),
		fleetSvc:    service.NewFleetService(db),
		trackingSvc: service.NewTrackingService(db),
		jwtSecret:   jwtSecret,
		db:          db,
		startTime:   time.Now(),
	}

	gw.registerRoutes()

	// Gateway-level CORS and middleware
	return gw.withMiddleware(gw.mux), nil
}

func (gw *GatewayMux) registerRoutes() {
	// Vehicle endpoints
	gw.mux.HandleFunc("/api/v1/vehicles", gw.handleVehicles)
	gw.mux.HandleFunc("/api/v1/vehicles/", gw.handleVehicleByID)

	// Route endpoints
	gw.mux.HandleFunc("/api/v1/routes", gw.handleRoutes)
	gw.mux.HandleFunc("/api/v1/routes/", gw.handleRouteByID)

	// Driver endpoints
	gw.mux.HandleFunc("/api/v1/drivers", gw.handleDrivers)
	gw.mux.HandleFunc("/api/v1/drivers/", gw.handleDriverByID)

	// Auth endpoints
	gw.mux.HandleFunc("/api/v1/auth/login", gw.handleLogin)

	// Stats & admin
	gw.mux.HandleFunc("/api/v1/stats", gw.handleStats)
	gw.mux.HandleFunc("/api/v1/health", gw.handleHealth)
	gw.mux.HandleFunc("/api/v1/debug", gw.handleDebug)
}

func (gw *GatewayMux) withMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS middleware - wildcard origin allows any site to make authenticated requests
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// No security headers set (see Dockerfile/infra for related bugs)
		h.ServeHTTP(w, r)
	})
}

// handleVehicles handles /api/v1/vehicles.
func (gw *GatewayMux) handleVehicles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		pageSize := int32(100)
		pageToken := r.URL.Query().Get("page_token")
		filter := r.URL.Query().Get("filter")
		orderBy := r.URL.Query().Get("order_by")

		vh := handler.NewVehicleHandler(gw.fleetSvc)
		resp, err := vh.ListVehicles(ctx, &handler.ListVehiclesRequest{
			PageSize:  pageSize,
			PageToken: pageToken,
			Filter:    filter,
			OrderBy:   orderBy,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		var req handler.CreateVehicleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		vh := handler.NewVehicleHandler(gw.fleetSvc)
		resp, err := vh.CreateVehicle(ctx, &req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleVehicleByID handles /api/v1/vehicles/{id}.
func (gw *GatewayMux) handleVehicleByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/vehicles/")

	// Strip trailing path segments for sub-resources
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}

	vh := handler.NewVehicleHandler(gw.fleetSvc)

	switch r.Method {
	case http.MethodGet:
		resp, err := vh.GetVehicle(ctx, &handler.GetVehicleRequest{ID: id})
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPut:
		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		resp, err := vh.UpdateVehicle(ctx, &handler.UpdateVehicleRequest{ID: id, Vehicle: body})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodDelete:
		_, err := vh.DeleteVehicle(ctx, &handler.DeleteVehicleRequest{ID: id})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRoutes handles /api/v1/routes.
func (gw *GatewayMux) handleRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		rh := handler.NewRouteHandler(gw.fleetSvc)
		resp, err := rh.ListRoutes(ctx, &handler.ListRoutesRequest{
			PageSize:  100,
			PageToken: r.URL.Query().Get("page_token"),
			DriverID:  r.URL.Query().Get("driver_id"),
			VehicleID: r.URL.Query().Get("vehicle_id"),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		var req handler.CreateRouteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		rh := handler.NewRouteHandler(gw.fleetSvc)
		resp, err := rh.CreateRoute(ctx, &req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRouteByID handles /api/v1/routes/{id} and sub-routes.
func (gw *GatewayMux) handleRouteByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/routes/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]

	rh := handler.NewRouteHandler(gw.fleetSvc)

	// Check for sub-routes
	if len(parts) == 2 {
		switch parts[1] {
		case "assign":
			var req handler.AssignRouteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			req.RouteID = id
			resp, err := rh.AssignRoute(ctx, &req)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return

		case "complete":
			var req handler.CompleteRouteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			req.RouteID = id
			resp, err := rh.CompleteRoute(ctx, &req)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// Default: get route
	if r.Method == http.MethodGet {
		resp, err := rh.GetRoute(ctx, &handler.GetRouteRequest{ID: id})
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleDrivers handles /api/v1/drivers.
func (gw *GatewayMux) handleDrivers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		dh := handler.NewDriverHandler(gw.fleetSvc, gw.trackingSvc, gw.jwtSecret)
		resp, err := dh.ListDrivers(ctx, &handler.ListDriversRequest{
			PageSize:  100,
			PageToken: r.URL.Query().Get("page_token"),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		var req handler.RegisterDriverRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		dh := handler.NewDriverHandler(gw.fleetSvc, gw.trackingSvc, gw.jwtSecret)
		resp, err := dh.RegisterDriver(ctx, &req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleDriverByID handles /api/v1/drivers/{id} and sub-routes.
func (gw *GatewayMux) handleDriverByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/drivers/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]

	dh := handler.NewDriverHandler(gw.fleetSvc, gw.trackingSvc, gw.jwtSecret)

	if len(parts) == 2 && parts[1] == "status" {
		var req handler.UpdateDriverStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.DriverID = id
		resp, err := dh.UpdateDriverStatus(ctx, &req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if r.Method == http.MethodGet {
		resp, err := dh.GetDriver(ctx, &handler.GetDriverRequest{ID: id})
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleLogin handles /api/v1/auth/login.
func (gw *GatewayMux) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req handler.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dh := handler.NewDriverHandler(gw.fleetSvc, gw.trackingSvc, gw.jwtSecret)
	resp, err := dh.Login(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleStats handles /api/v1/stats.
func (gw *GatewayMux) handleStats(w http.ResponseWriter, r *http.Request) {
	tv, av, td, ar, af, tm, err := gw.fleetSvc.GetFleetStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_vehicles":  tv,
		"active_vehicles": av,
		"total_drivers":   td,
		"active_routes":   ar,
		"avg_fuel_level":  af,
		"total_mileage":   tm,
	})
}

// handleHealth handles /api/v1/health.
func (gw *GatewayMux) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus := "connected"
	sqlDB, err := gw.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		dbStatus = "disconnected"
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "ok",
		"version":           "1.4.2-dev",
		"database_status":   dbStatus,
		"database_host":     os.Getenv("DATABASE_URL"),
		"uptime_seconds":    int64(time.Since(gw.startTime).Seconds()),
		"go_version":        runtime.Version(),
		"goroutine_count":   runtime.NumGoroutine(),
		"memory_alloc_bytes": memStats.Alloc,
	})
}

// handleDebug handles /api/v1/debug.
func (gw *GatewayMux) handleDebug(w http.ResponseWriter, r *http.Request) {
	envVars := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}

	var configs []model.FleetConfig
	gw.db.Find(&configs)
	configMap := make(map[string]string)
	for _, c := range configs {
		configMap[c.Key] = c.Value
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config":             configMap,
		"env_vars":           envVars,
		"active_connections": runtime.NumGoroutine(),
		"registered_services": []string{
			"fleet.v1.FleetService",
			"fleet.gateway.v1.FleetGateway",
			"grpc.reflection.v1alpha.ServerReflection",
		},
	})
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{
		"error":   http.StatusText(code),
		"message": message,
	})
}

// corsOriginAllowed checks if origin is in the allowlist.
// Currently unused because CORS is set to wildcard.
func corsOriginAllowed(origin string) bool {
	allowed := []string{
		"https://dashboard.bonecorp.io",
		"https://admin.bonecorp.io",
	}
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

// extractIDFromPath extracts the resource ID from a URL path.
func extractIDFromPath(path, prefix string) string {
	id := strings.TrimPrefix(path, prefix)
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}
	return id
}

// formatUptime formats duration as human-readable string.
func formatUptime(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", hours, minutes)
}
