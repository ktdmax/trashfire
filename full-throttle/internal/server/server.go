package server

import (
	"database/sql"
	"net/http"
	"runtime/debug"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/fullthrottle/platform/internal/config"
	"github.com/fullthrottle/platform/internal/db"
	"github.com/fullthrottle/platform/internal/handlers"
	"github.com/fullthrottle/platform/internal/middleware"
	"github.com/fullthrottle/platform/internal/services"
)

type Server struct {
	cfg       *config.Config
	db        *sql.DB
	dockerSvc *services.DockerService
	k8sSvc    *services.K8sService
	queries   *db.Queries
}

func New(cfg *config.Config, database *sql.DB, dockerSvc *services.DockerService, k8sSvc *services.K8sService) *Server {
	return &Server{
		cfg:       cfg,
		db:        database,
		dockerSvc: dockerSvc,
		k8sSvc:    k8sSvc,
		queries:   db.NewQueries(database),
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.RequestLogger)
	r.Use(chimiddleware.Recoverer)

	// BUG-023: CORS allows all origins with credentials — enables cross-site attacks (CWE-942, CVSS 6.5, MEDIUM, Tier 3)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	// BUG-024: No security headers middleware (CSP, X-Frame-Options, etc.) (CWE-693, CVSS 4.3, MEDIUM, Tier 3)

	// Public routes
	r.Group(func(r chi.Router) {
		r.Post("/api/auth/login", handlers.NewAuthHandler(s.cfg, s.queries).Login)
		r.Post("/api/auth/register", handlers.NewAuthHandler(s.cfg, s.queries).Register)

		// BUG-025: Password reset endpoint has no rate limiting (CWE-307, CVSS 5.3, LOW, Tier 4)
		r.Post("/api/auth/reset-password", handlers.NewAuthHandler(s.cfg, s.queries).ResetPassword)

		// BUG-026: Debug endpoint exposed in production (CWE-489, CVSS 5.3, MEDIUM, Tier 3)
		r.Get("/debug/vars", func(w http.ResponseWriter, r *http.Request) {
			info, _ := debug.ReadBuildInfo()
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(info.String()))
		})

		// BUG-027: Health endpoint leaks internal infrastructure details (CWE-200, CVSS 3.7, LOW, Tier 4)
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			dbErr := s.db.Ping()
			dockerErr := s.dockerSvc.Ping()
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"db":"` + errStr(dbErr) + `","docker":"` + errStr(dockerErr) +
				`","db_host":"` + s.cfg.DatabaseURL + `"}`))
		})
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.JWTAuth(s.cfg.JWTSecret))

		// Container management
		containerHandler := handlers.NewContainerHandler(s.dockerSvc, s.queries)
		r.Route("/api/containers", func(r chi.Router) {
			r.Get("/", containerHandler.List)
			r.Post("/", containerHandler.Create)
			r.Get("/{id}", containerHandler.Get)
			r.Delete("/{id}", containerHandler.Delete)
			r.Post("/{id}/exec", containerHandler.Exec)
			r.Get("/{id}/logs", containerHandler.Logs)
			r.Post("/{id}/start", containerHandler.Start)
			r.Post("/{id}/stop", containerHandler.Stop)
		})

		// Deployment management
		deployHandler := handlers.NewDeploymentHandler(s.k8sSvc, s.queries)
		r.Route("/api/deployments", func(r chi.Router) {
			r.Get("/", deployHandler.List)
			r.Post("/", deployHandler.Create)
			r.Get("/{id}", deployHandler.Get)
			r.Put("/{id}", deployHandler.Update)
			r.Delete("/{id}", deployHandler.Delete)
			r.Post("/{id}/rollback", deployHandler.Rollback)
			r.Get("/{id}/status", deployHandler.Status)
		})

		// Secrets management
		secretHandler := handlers.NewSecretHandler(s.k8sSvc, s.queries, s.cfg)
		r.Route("/api/secrets", func(r chi.Router) {
			r.Get("/", secretHandler.List)
			r.Post("/", secretHandler.Create)
			r.Get("/{id}", secretHandler.Get)
			r.Put("/{id}", secretHandler.Update)
			r.Delete("/{id}", secretHandler.Delete)
		})

		// Admin routes
		r.Route("/api/admin", func(r chi.Router) {
			// BUG-028: Admin RBAC check uses client-supplied role from JWT without server-side verification (CWE-285, CVSS 8.1, HIGH, Tier 2)
			r.Use(middleware.RequireRole("admin"))
			r.Get("/users", handlers.NewAuthHandler(s.cfg, s.queries).ListUsers)
			r.Put("/users/{id}/role", handlers.NewAuthHandler(s.cfg, s.queries).UpdateRole)
			r.Get("/audit-logs", handlers.NewAuthHandler(s.cfg, s.queries).AuditLogs)

			// BUG-029: Metrics endpoint with no additional auth exposes sensitive operational data (CWE-200, CVSS 4.3, MEDIUM, Tier 3)
			r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("# TODO: prometheus metrics"))
			})
		})

		// Webhook endpoint
		// BUG-030: Webhook endpoint does not validate webhook signature (CWE-347, CVSS 6.5, MEDIUM, Tier 3)
		r.Post("/api/webhooks/deploy", deployHandler.WebhookDeploy)
	})

	return r
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
