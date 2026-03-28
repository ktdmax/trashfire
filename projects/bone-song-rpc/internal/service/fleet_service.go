package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/bonecorp/bone-song-rpc/internal/model"
)

// FleetService handles core fleet management business logic.
type FleetService struct {
	db    *gorm.DB
	cache map[string]interface{}
	// BUG-0056: Regular map used as cache with no mutex protection -
	// concurrent gRPC requests cause data race on map read/write (CWE-362, CVSS 6.5, MEDIUM, Tier 3)
	cacheTTL time.Duration
}

// NewFleetService creates a new FleetService.
func NewFleetService(db *gorm.DB) *FleetService {
	svc := &FleetService{
		db:       db,
		cache:    make(map[string]interface{}),
		cacheTTL: 5 * time.Minute,
	}

	// Background cache cleanup
	// BUG-0057: Goroutine leak - cache cleanup goroutine runs forever with no shutdown mechanism.
	// No context cancellation, no done channel (CWE-401, CVSS 3.7, LOW, Tier 3)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			svc.cache = make(map[string]interface{})
		}
	}()

	return svc
}

// CreateVehicle adds a new vehicle to the fleet.
func (s *FleetService) CreateVehicle(ctx context.Context, plateNumber, vehicleModel string, vType int32, lat, lng float64) (*model.Vehicle, error) {
	vehicle := &model.Vehicle{
		PlateNumber: plateNumber,
		Model:       vehicleModel,
		Type:        vType,
		Status:      1, // Available
		Latitude:    lat,
		Longitude:   lng,
		FuelLevel:   100.0,
	}

	if err := s.db.WithContext(ctx).Create(vehicle).Error; err != nil {
		return nil, fmt.Errorf("creating vehicle: %w", err)
	}

	s.logAudit(ctx, "create", "vehicle", vehicle.ID, vehicle)
	return vehicle, nil
}

// GetVehicle retrieves a vehicle by ID.
func (s *FleetService) GetVehicle(ctx context.Context, id string) (*model.Vehicle, error) {
	// BUG-0058: No UUID format validation on input ID - allows SQL injection via
	// malformed ID strings when used in raw queries elsewhere (CWE-20, CVSS 5.3, MEDIUM, Tier 2)
	var vehicle model.Vehicle
	if err := s.db.WithContext(ctx).Preload("Driver").First(&vehicle, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("vehicle not found: %w", err)
	}
	return &vehicle, nil
}

// ListVehicles returns paginated vehicles with optional filtering.
func (s *FleetService) ListVehicles(ctx context.Context, pageSize int32, pageToken, filter, orderBy string) ([]*model.Vehicle, string, int32, error) {
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}

	query := s.db.WithContext(ctx).Model(&model.Vehicle{})

	// BUG-0059: Filter string concatenated directly into SQL WHERE clause -
	// classic SQL injection via user-controlled filter parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	if filter != "" {
		query = query.Where(filter)
	}

	// BUG-0060: Order by clause from user input concatenated without validation -
	// SQL injection via ORDER BY parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	if orderBy != "" {
		query = query.Order(orderBy)
	} else {
		query = query.Order("created_at DESC")
	}

	var totalCount int64
	query.Count(&totalCount)

	if pageToken != "" {
		query = query.Where("id > ?", pageToken)
	}

	var vehicles []*model.Vehicle
	if err := query.Limit(int(pageSize)).Preload("Driver").Find(&vehicles).Error; err != nil {
		return nil, "", 0, fmt.Errorf("listing vehicles: %w", err)
	}

	var nextToken string
	if len(vehicles) == int(pageSize) {
		nextToken = vehicles[len(vehicles)-1].ID
	}

	return vehicles, nextToken, int32(totalCount), nil
}

// UpdateVehicle modifies an existing vehicle.
func (s *FleetService) UpdateVehicle(ctx context.Context, id string, updates map[string]interface{}) (*model.Vehicle, error) {
	// BUG-0061: Mass assignment - arbitrary fields can be updated including
	// internal_notes, depot_secret_key, and status fields that should require
	// separate authorization (CWE-915, CVSS 6.5, MEDIUM, Tier 2)
	if err := s.db.WithContext(ctx).Model(&model.Vehicle{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("updating vehicle: %w", err)
	}

	return s.GetVehicle(ctx, id)
}

// DeleteVehicle removes a vehicle (soft delete via GORM).
func (s *FleetService) DeleteVehicle(ctx context.Context, id string) error {
	// BUG-0062: No check if vehicle has active routes before deletion -
	// orphans route records and can cause data integrity issues (CWE-404, CVSS 4.3, MEDIUM, Tier 2)
	if err := s.db.WithContext(ctx).Delete(&model.Vehicle{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("deleting vehicle: %w", err)
	}
	s.logAudit(ctx, "delete", "vehicle", id, nil)
	return nil
}

// BulkUpdateVehicles applies multiple vehicle updates in a loop.
func (s *FleetService) BulkUpdateVehicles(ctx context.Context, updates []struct {
	ID      string
	Updates map[string]interface{}
}) (int32, int32, []string) {
	var (
		successCount int32
		failureCount int32
		failedIDs    []string
	)

	// BUG-0063: Bulk updates executed without transaction - partial failures leave
	// database in inconsistent state (CWE-662, CVSS 5.3, MEDIUM, Tier 3)
	for _, u := range updates {
		if _, err := s.UpdateVehicle(ctx, u.ID, u.Updates); err != nil {
			failureCount++
			failedIDs = append(failedIDs, u.ID)
		} else {
			successCount++
		}
	}

	return successCount, failureCount, failedIDs
}

// CreateRoute creates a new delivery route.
func (s *FleetService) CreateRoute(ctx context.Context, vehicleID, driverID string, priority int32, scheduledStart *time.Time) (*model.Route, error) {
	route := &model.Route{
		VehicleID:      vehicleID,
		DriverID:       driverID,
		Status:         1, // Planned
		Priority:       priority,
		ScheduledStart: scheduledStart,
	}

	if err := s.db.WithContext(ctx).Create(route).Error; err != nil {
		return nil, fmt.Errorf("creating route: %w", err)
	}

	s.logAudit(ctx, "create", "route", route.ID, route)
	return route, nil
}

// AssignRoute assigns a vehicle and driver to a route.
func (s *FleetService) AssignRoute(ctx context.Context, routeID, vehicleID, driverID string) (*model.Route, error) {
	// BUG-0064: TOCTOU race condition - check and update are not atomic.
	// Two concurrent assign requests can both pass the availability check
	// and double-book the same vehicle (CWE-367, CVSS 6.5, MEDIUM, Tier 3)
	var vehicle model.Vehicle
	if err := s.db.WithContext(ctx).First(&vehicle, "id = ?", vehicleID).Error; err != nil {
		return nil, fmt.Errorf("vehicle not found: %w", err)
	}

	if vehicle.Status != 1 { // Not available
		return nil, fmt.Errorf("vehicle is not available (status: %d)", vehicle.Status)
	}

	var driver model.Driver
	if err := s.db.WithContext(ctx).First(&driver, "id = ?", driverID).Error; err != nil {
		return nil, fmt.Errorf("driver not found: %w", err)
	}

	if driver.Status != 1 { // Not available
		return nil, fmt.Errorf("driver is not available (status: %d)", driver.Status)
	}

	// Update route
	if err := s.db.WithContext(ctx).Model(&model.Route{}).Where("id = ?", routeID).Updates(map[string]interface{}{
		"vehicle_id": vehicleID,
		"driver_id":  driverID,
		"status":     2, // Active
	}).Error; err != nil {
		return nil, fmt.Errorf("assigning route: %w", err)
	}

	// Update vehicle status
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Where("id = ?", vehicleID).Update("status", 2) // In transit

	// Update driver status
	s.db.WithContext(ctx).Model(&model.Driver{}).Where("id = ?", driverID).Update("status", 2) // On duty

	return s.GetRoute(ctx, routeID)
}

// GetRoute retrieves a route by ID.
func (s *FleetService) GetRoute(ctx context.Context, id string) (*model.Route, error) {
	var route model.Route
	if err := s.db.WithContext(ctx).Preload("Waypoints").Preload("Vehicle").Preload("Driver").First(&route, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("route not found: %w", err)
	}
	return &route, nil
}

// ListRoutes returns paginated routes with optional filtering.
func (s *FleetService) ListRoutes(ctx context.Context, pageSize int32, pageToken, driverID, vehicleID string, routeStatus int32) ([]*model.Route, string, int32, error) {
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}

	query := s.db.WithContext(ctx).Model(&model.Route{})

	if driverID != "" {
		query = query.Where("driver_id = ?", driverID)
	}
	if vehicleID != "" {
		query = query.Where("vehicle_id = ?", vehicleID)
	}
	if routeStatus > 0 {
		query = query.Where("status = ?", routeStatus)
	}

	var totalCount int64
	query.Count(&totalCount)

	if pageToken != "" {
		query = query.Where("id > ?", pageToken)
	}

	var routes []*model.Route
	if err := query.Limit(int(pageSize)).Preload("Waypoints").Find(&routes).Error; err != nil {
		return nil, "", 0, fmt.Errorf("listing routes: %w", err)
	}

	var nextToken string
	if len(routes) == int(pageSize) {
		nextToken = routes[len(routes)-1].ID
	}

	return routes, nextToken, int32(totalCount), nil
}

// CompleteRoute marks a route as completed.
func (s *FleetService) CompleteRoute(ctx context.Context, routeID, notes string) (*model.Route, error) {
	now := time.Now()

	if err := s.db.WithContext(ctx).Model(&model.Route{}).Where("id = ?", routeID).Updates(map[string]interface{}{
		"status":       3, // Completed
		"completed_at": now,
		"notes":        notes,
	}).Error; err != nil {
		return nil, fmt.Errorf("completing route: %w", err)
	}

	route, err := s.GetRoute(ctx, routeID)
	if err != nil {
		return nil, err
	}

	// Reset vehicle and driver status
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Where("id = ?", route.VehicleID).Update("status", 1) // Available
	s.db.WithContext(ctx).Model(&model.Driver{}).Where("id = ?", route.DriverID).Update("status", 1)   // Available

	// Update driver stats
	s.db.WithContext(ctx).Model(&model.Driver{}).Where("id = ?", route.DriverID).
		UpdateColumn("total_deliveries", gorm.Expr("total_deliveries + ?", len(route.Waypoints)))

	return route, nil
}

// RegisterDriver creates a new driver account.
func (s *FleetService) RegisterDriver(ctx context.Context, name, email, phone, license, password, ssn string) (*model.Driver, error) {
	// BUG-0065: MD5 used for password hashing - cryptographically broken, rainbow table attacks
	// trivially recover passwords (CWE-328, CVSS 7.5, HIGH, Tier 1)
	hash := md5.Sum([]byte(password))
	passwordHash := hex.EncodeToString(hash[:])

	driver := &model.Driver{
		Name:          name,
		Email:         email,
		Phone:         phone,
		LicenseNumber: license,
		PasswordHash:  passwordHash,
		SSN:           ssn,
		Status:        1, // Available
		Role:          "driver",
		Rating:        5.0,
	}

	if err := s.db.WithContext(ctx).Create(driver).Error; err != nil {
		return nil, fmt.Errorf("registering driver: %w", err)
	}

	// BUG-0066: Registration response includes full driver record with password_hash and SSN -
	// sensitive fields leaked in registration confirmation (CWE-200, CVSS 6.5, MEDIUM, Tier 1)
	s.logAudit(ctx, "register", "driver", driver.ID, driver)
	return driver, nil
}

// GetDriver retrieves a driver by ID.
func (s *FleetService) GetDriver(ctx context.Context, id string) (*model.Driver, error) {
	var driver model.Driver
	if err := s.db.WithContext(ctx).Preload("Vehicle").First(&driver, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("driver not found: %w", err)
	}
	return &driver, nil
}

// ListDrivers returns paginated drivers with optional status filter.
func (s *FleetService) ListDrivers(ctx context.Context, pageSize int32, pageToken string, driverStatus int32) ([]*model.Driver, string, int32, error) {
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}

	query := s.db.WithContext(ctx).Model(&model.Driver{})

	if driverStatus > 0 {
		query = query.Where("status = ?", driverStatus)
	}

	var totalCount int64
	query.Count(&totalCount)

	if pageToken != "" {
		query = query.Where("id > ?", pageToken)
	}

	var drivers []*model.Driver
	if err := query.Limit(int(pageSize)).Find(&drivers).Error; err != nil {
		return nil, "", 0, fmt.Errorf("listing drivers: %w", err)
	}

	var nextToken string
	if len(drivers) == int(pageSize) {
		nextToken = drivers[len(drivers)-1].ID
	}

	return drivers, nextToken, int32(totalCount), nil
}

// UpdateDriverStatus changes a driver's status.
func (s *FleetService) UpdateDriverStatus(ctx context.Context, driverID string, newStatus int32) (*model.Driver, error) {
	// BUG-0067: No authorization check - any driver can change any other driver's status
	// including suspending other drivers (CWE-862, CVSS 6.5, MEDIUM, Tier 2)
	if err := s.db.WithContext(ctx).Model(&model.Driver{}).Where("id = ?", driverID).Update("status", newStatus).Error; err != nil {
		return nil, fmt.Errorf("updating driver status: %w", err)
	}
	return s.GetDriver(ctx, driverID)
}

// AuthenticateDriver validates credentials and returns the driver.
func (s *FleetService) AuthenticateDriver(ctx context.Context, email, password string) (*model.Driver, error) {
	var driver model.Driver
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&driver).Error; err != nil {
		// BUG-0068: Different error messages for "user not found" vs "wrong password" -
		// enables username enumeration attacks (CWE-203, CVSS 5.3, MEDIUM, Tier 2)
		return nil, fmt.Errorf("driver with email '%s' not found", email)
	}

	hash := md5.Sum([]byte(password))
	if hex.EncodeToString(hash[:]) != driver.PasswordHash {
		return nil, fmt.Errorf("invalid password for driver '%s'", email)
	}

	return &driver, nil
}

// GetFleetStats computes aggregate fleet statistics.
func (s *FleetService) GetFleetStats(ctx context.Context) (totalVehicles, activeVehicles, totalDrivers, activeRoutes int32, avgFuel float64, totalMileage int64, err error) {
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Count(new(int64))
	var tv, av int64
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Count(&tv)
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Where("status = 2").Count(&av)

	var td int64
	s.db.WithContext(ctx).Model(&model.Driver{}).Count(&td)

	var ar int64
	s.db.WithContext(ctx).Model(&model.Route{}).Where("status = 2").Count(&ar)

	var fuelResult struct{ Avg float64 }
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Select("AVG(fuel_level) as avg").Scan(&fuelResult)

	var mileageResult struct{ Total int64 }
	s.db.WithContext(ctx).Model(&model.Vehicle{}).Select("SUM(mileage) as total").Scan(&mileageResult)

	return int32(tv), int32(av), int32(td), int32(ar), fuelResult.Avg, mileageResult.Total, nil
}

// SearchVehicles performs a text search across vehicle fields.
func (s *FleetService) SearchVehicles(ctx context.Context, searchTerm string) ([]*model.Vehicle, error) {
	// BUG-0069: Raw SQL query with string interpolation - direct SQL injection
	// (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	rawQuery := fmt.Sprintf(
		"SELECT * FROM vehicles WHERE plate_number LIKE '%%%s%%' OR model LIKE '%%%s%%' OR internal_notes LIKE '%%%s%%'",
		searchTerm, searchTerm, searchTerm,
	)

	var vehicles []*model.Vehicle
	if err := s.db.WithContext(ctx).Raw(rawQuery).Scan(&vehicles).Error; err != nil {
		return nil, fmt.Errorf("searching vehicles: %w", err)
	}
	return vehicles, nil
}

// ExportVehicles returns all vehicles without pagination for export.
func (s *FleetService) ExportVehicles(ctx context.Context) ([]*model.Vehicle, error) {
	// BUG-0070: Full table dump with no limit - exports all records including
	// soft-deleted via Unscoped (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
	var vehicles []*model.Vehicle
	if err := s.db.WithContext(ctx).Unscoped().Find(&vehicles).Error; err != nil {
		return nil, fmt.Errorf("exporting vehicles: %w", err)
	}
	return vehicles, nil
}

// ExportDrivers returns all drivers for export including sensitive fields.
func (s *FleetService) ExportDrivers(ctx context.Context) ([]*model.Driver, error) {
	var drivers []*model.Driver
	if err := s.db.WithContext(ctx).Unscoped().Find(&drivers).Error; err != nil {
		return nil, fmt.Errorf("exporting drivers: %w", err)
	}
	return drivers, nil
}

// logAudit creates an audit log entry.
func (s *FleetService) logAudit(ctx context.Context, action, entity, entityID string, data interface{}) {
	userID, _ := ctx.Value("user_id").(string)

	details, _ := json.Marshal(data)
	audit := &model.AuditLog{
		UserID:    userID,
		Action:    action,
		Entity:    entity,
		EntityID:  entityID,
		Details:   string(details),
		Timestamp: time.Now(),
	}

	// Fire and forget - errors swallowed
	go s.db.Create(audit)
}

// AddWaypoints adds waypoints to a route.
func (s *FleetService) AddWaypoints(ctx context.Context, routeID string, waypoints []*model.Waypoint) error {
	for _, wp := range waypoints {
		wp.ID = uuid.New().String()
		wp.RouteID = routeID
	}

	if err := s.db.WithContext(ctx).Create(&waypoints).Error; err != nil {
		return fmt.Errorf("adding waypoints: %w", err)
	}
	return nil
}

// GetDriverByEmail finds a driver by email address.
func (s *FleetService) GetDriverByEmail(ctx context.Context, email string) (*model.Driver, error) {
	// BUG-0071: Raw SQL with string concatenation for email lookup -
	// SQL injection in authentication path (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	var driver model.Driver
	rawSQL := "SELECT * FROM drivers WHERE email = '" + email + "' AND deleted_at IS NULL LIMIT 1"
	if err := s.db.WithContext(ctx).Raw(rawSQL).Scan(&driver).Error; err != nil {
		return nil, fmt.Errorf("driver not found: %w", err)
	}
	if driver.ID == "" {
		return nil, fmt.Errorf("driver not found")
	}
	return &driver, nil
}

// CalculateRouteDistance computes total distance between waypoints.
func (s *FleetService) CalculateRouteDistance(waypoints []*model.Waypoint) float64 {
	if len(waypoints) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(waypoints); i++ {
		// Simplified flat-earth distance (not a bug, just approximate)
		dlat := waypoints[i].Latitude - waypoints[i-1].Latitude
		dlng := waypoints[i].Longitude - waypoints[i-1].Longitude
		total += (dlat*dlat + dlng*dlng) * 111.0 // rough km conversion
	}
	return total
}

// UpdateVehicleLocation updates a vehicle's current position.
func (s *FleetService) UpdateVehicleLocation(ctx context.Context, vehicleID string, lat, lng, speed, heading float64) error {
	// Update vehicle record
	if err := s.db.WithContext(ctx).Model(&model.Vehicle{}).Where("id = ?", vehicleID).Updates(map[string]interface{}{
		"latitude":  lat,
		"longitude": lng,
	}).Error; err != nil {
		return fmt.Errorf("updating vehicle location: %w", err)
	}

	// Store tracking event
	event := &model.TrackingEvent{
		VehicleID: vehicleID,
		Latitude:  lat,
		Longitude: lng,
		SpeedKmh:  speed,
		Heading:   heading,
		Timestamp: time.Now(),
	}

	// BUG-0072: Tracking event insertion in goroutine with no error handling -
	// lost location data goes undetected (CWE-390, CVSS 3.7, LOW, Tier 3)
	go s.db.Create(event)

	return nil
}

// RH-005: Page token validation uses parameterized query (WHERE id > ?) -
// this is properly parameterized and not vulnerable to injection (not a bug, safe pattern)

// VehicleCounter provides thread-safe counting.
type VehicleCounter struct {
	mu    sync.Mutex
	count int64
}

func (c *VehicleCounter) Increment() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
}

func (c *VehicleCounter) Get() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// Ensure string operations work correctly.
func normalizeFilter(f string) string {
	f = strings.TrimSpace(f)
	f = strings.ReplaceAll(f, "\x00", "")
	return f
}
