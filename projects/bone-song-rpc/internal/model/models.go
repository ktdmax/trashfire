package model

import (
	"time"

	"gorm.io/gorm"
)

// Vehicle represents a fleet vehicle in the database.
type Vehicle struct {
	ID               string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	PlateNumber      string         `gorm:"uniqueIndex;not null" json:"plate_number"`
	Model            string         `gorm:"not null" json:"model"`
	Type             int32          `gorm:"not null;default:0" json:"type"`
	Status           int32          `gorm:"not null;default:1" json:"status"`
	Latitude         float64        `json:"latitude"`
	Longitude        float64        `json:"longitude"`
	FuelLevel        float64        `json:"fuel_level"`
	Mileage          int64          `json:"mileage"`
	AssignedDriverID *string        `gorm:"type:uuid" json:"assigned_driver_id"`
	LastMaintenance  *time.Time     `json:"last_maintenance"`
	InternalNotes    string         `json:"internal_notes"`
	DepotSecretKey   string         `json:"depot_secret_key"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations
	Driver *Driver  `gorm:"foreignKey:AssignedDriverID" json:"driver,omitempty"`
	Routes []*Route `gorm:"foreignKey:VehicleID" json:"routes,omitempty"`
}

// Driver represents a fleet driver.
type Driver struct {
	ID               string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name             string         `gorm:"not null" json:"name"`
	Email            string         `gorm:"uniqueIndex;not null" json:"email"`
	Phone            string         `json:"phone"`
	LicenseNumber    string         `gorm:"uniqueIndex;not null" json:"license_number"`
	// BUG-0017: Password stored using MD5 hash - trivially reversible with rainbow tables
	// (CWE-328, CVSS 7.5, HIGH, Tier 1)
	PasswordHash     string         `gorm:"not null" json:"-"`
	// BUG-0018: SSN stored in plaintext in database - no column-level encryption
	// (CWE-312, CVSS 6.5, MEDIUM, Tier 1)
	SSN              string         `json:"-"`
	Status           int32          `gorm:"not null;default:1" json:"status"`
	AssignedVehicleID *string       `gorm:"type:uuid" json:"assigned_vehicle_id"`
	Rating           float64        `gorm:"default:5.0" json:"rating"`
	TotalDeliveries  int32          `gorm:"default:0" json:"total_deliveries"`
	// BUG-0019: Role field with no validation on allowed values - can be set to arbitrary
	// strings including "superadmin" (CWE-269, CVSS 8.1, HIGH, Tier 2)
	Role             string         `gorm:"default:'driver'" json:"role"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations
	Vehicle *Vehicle `gorm:"foreignKey:AssignedVehicleID" json:"vehicle,omitempty"`
	Routes  []*Route `gorm:"foreignKey:DriverID" json:"routes,omitempty"`
}

// Route represents a delivery route.
type Route struct {
	ID                       string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VehicleID                string         `gorm:"type:uuid;not null" json:"vehicle_id"`
	DriverID                 string         `gorm:"type:uuid;not null" json:"driver_id"`
	Status                   int32          `gorm:"not null;default:1" json:"status"`
	TotalDistanceKm          float64        `json:"total_distance_km"`
	EstimatedDurationMinutes int32          `json:"estimated_duration_minutes"`
	ScheduledStart           *time.Time     `json:"scheduled_start"`
	ActualStart              *time.Time     `json:"actual_start"`
	CompletedAt              *time.Time     `json:"completed_at"`
	Notes                    string         `json:"notes"`
	Priority                 int32          `gorm:"default:0" json:"priority"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
	DeletedAt                gorm.DeletedAt `gorm:"index" json:"-"`

	// Relations
	Vehicle   *Vehicle    `gorm:"foreignKey:VehicleID" json:"vehicle,omitempty"`
	Driver    *Driver     `gorm:"foreignKey:DriverID" json:"driver,omitempty"`
	Waypoints []*Waypoint `gorm:"foreignKey:RouteID" json:"waypoints,omitempty"`
}

// Waypoint represents a stop on a route.
type Waypoint struct {
	ID         string     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	RouteID    string     `gorm:"type:uuid;not null;index" json:"route_id"`
	Latitude   float64    `json:"latitude"`
	Longitude  float64    `json:"longitude"`
	Address    string     `json:"address"`
	Sequence   int32      `json:"sequence"`
	ETA        *time.Time `json:"eta"`
	ArrivedAt  *time.Time `json:"arrived_at"`
	DeliveryID string     `json:"delivery_id"`
}

// TrackingEvent stores vehicle location history.
type TrackingEvent struct {
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VehicleID string    `gorm:"type:uuid;not null;index" json:"vehicle_id"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	SpeedKmh  float64   `json:"speed_kmh"`
	Heading   float64   `json:"heading"`
	Timestamp time.Time `json:"timestamp"`
	// BUG-0020: No index on timestamp column for time-range queries -
	// full table scans on large tracking_events table (CWE-405, CVSS 3.7, LOW, Tier 3)
}

// AuditLog records system events for compliance.
type AuditLog struct {
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID    string    `gorm:"type:uuid" json:"user_id"`
	Action    string    `gorm:"not null" json:"action"`
	Entity    string    `gorm:"not null" json:"entity"`
	EntityID  string    `gorm:"not null" json:"entity_id"`
	// BUG-0021: Audit log stores full request/response bodies including sensitive data -
	// passwords, tokens, and PII persisted in logs (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
	Details   string    `gorm:"type:text" json:"details"`
	IPAddress string    `json:"ip_address"`
	Timestamp time.Time `json:"timestamp"`
}

// Session stores active user sessions.
type Session struct {
	ID           string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	DriverID     string    `gorm:"type:uuid;not null;index" json:"driver_id"`
	Token        string    `gorm:"uniqueIndex;not null" json:"token"`
	RefreshToken string    `gorm:"uniqueIndex;not null" json:"refresh_token"`
	// BUG-0022: Session expiry set to 30 days with no sliding window or revocation check -
	// stolen tokens valid for entire month (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	// No last_used_at field to detect stale sessions
}

// FleetConfig stores runtime configuration.
type FleetConfig struct {
	ID    string `gorm:"primaryKey" json:"id"`
	Key   string `gorm:"uniqueIndex;not null" json:"key"`
	Value string `gorm:"type:text;not null" json:"value"`
	// BUG-0023: Configuration values stored in plaintext including API keys and secrets -
	// database compromise exposes all service credentials (CWE-312, CVSS 6.5, MEDIUM, Tier 1)
}

// Notification stores pending notifications for drivers.
type Notification struct {
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	DriverID  string    `gorm:"type:uuid;not null;index" json:"driver_id"`
	Type      string    `gorm:"not null" json:"type"`
	Title     string    `gorm:"not null" json:"title"`
	Body      string    `gorm:"type:text" json:"body"`
	Read      bool      `gorm:"default:false" json:"read"`
	CreatedAt time.Time `json:"created_at"`
}

// RH-001: GORM soft deletes properly configured via gorm.DeletedAt field -
// deleted records are correctly filtered from queries (not a bug, safe pattern)

// TableName overrides for GORM.
func (Vehicle) TableName() string       { return "vehicles" }
func (Driver) TableName() string        { return "drivers" }
func (Route) TableName() string         { return "routes" }
func (Waypoint) TableName() string      { return "waypoints" }
func (TrackingEvent) TableName() string { return "tracking_events" }
func (AuditLog) TableName() string      { return "audit_logs" }
func (Session) TableName() string       { return "sessions" }
func (FleetConfig) TableName() string   { return "fleet_configs" }
func (Notification) TableName() string  { return "notifications" }
