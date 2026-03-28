package handler

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bonecorp/bone-song-rpc/internal/interceptor"
	"github.com/bonecorp/bone-song-rpc/internal/model"
	"github.com/bonecorp/bone-song-rpc/internal/service"
)

// DriverHandler implements gRPC driver management endpoints.
type DriverHandler struct {
	fleetSvc    *service.FleetService
	trackingSvc *service.TrackingService
	jwtSecret   string
}

// NewDriverHandler creates a new DriverHandler.
func NewDriverHandler(fleetSvc *service.FleetService, trackingSvc *service.TrackingService, jwtSecret string) *DriverHandler {
	return &DriverHandler{
		fleetSvc:    fleetSvc,
		trackingSvc: trackingSvc,
		jwtSecret:   jwtSecret,
	}
}

// DriverProto is a simplified protobuf-like struct for driver responses.
type DriverProto struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Email            string                 `json:"email"`
	Phone            string                 `json:"phone"`
	LicenseNumber    string                 `json:"license_number"`
	Status           int32                  `json:"status"`
	AssignedVehicleID string                `json:"assigned_vehicle_id"`
	CreatedAt        *timestamppb.Timestamp `json:"created_at"`
	PasswordHash     string                 `json:"password_hash"`
	SSN              string                 `json:"ssn"`
	Rating           float64                `json:"rating"`
	TotalDeliveries  int32                  `json:"total_deliveries"`
}

// RegisterDriverRequest mirrors proto definition.
type RegisterDriverRequest struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	Phone         string `json:"phone"`
	LicenseNumber string `json:"license_number"`
	Password      string `json:"password"`
	SSN           string `json:"ssn"`
}

// GetDriverRequest mirrors proto definition.
type GetDriverRequest struct {
	ID string `json:"id"`
}

// ListDriversRequest mirrors proto definition.
type ListDriversRequest struct {
	PageSize  int32  `json:"page_size"`
	PageToken string `json:"page_token"`
	Status    int32  `json:"status"`
}

// ListDriversResponse mirrors proto definition.
type ListDriversResponse struct {
	Drivers       []*DriverProto `json:"drivers"`
	NextPageToken string         `json:"next_page_token"`
	TotalCount    int32          `json:"total_count"`
}

// UpdateDriverStatusRequest mirrors proto definition.
type UpdateDriverStatusRequest struct {
	DriverID string `json:"driver_id"`
	Status   int32  `json:"status"`
}

// LoginRequest mirrors proto definition.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse mirrors proto definition.
type LoginResponse struct {
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresIn    int64        `json:"expires_in"`
	Driver       *DriverProto `json:"driver"`
}

// RegisterDriver handles driver registration.
func (h *DriverHandler) RegisterDriver(ctx context.Context, req *RegisterDriverRequest) (*DriverProto, error) {
	// BUG-0095: No password complexity requirements - accepts empty or single-character
	// passwords (CWE-521, CVSS 5.3, MEDIUM, Tier 1)
	if req.Name == "" || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "name and email are required")
	}

	// BUG-0096: No email format validation - accepts arbitrary strings as email addresses,
	// can cause issues with notification systems (CWE-20, CVSS 3.7, LOW, Tier 2)

	driver, err := h.fleetSvc.RegisterDriver(ctx, req.Name, req.Email, req.Phone, req.LicenseNumber, req.Password, req.SSN)
	if err != nil {
		// BUG-0097: Database error leaked to client - reveals table structure and constraint names
		// (CWE-209, CVSS 3.7, LOW, Tier 2)
		return nil, status.Errorf(codes.Internal, "registration failed: %v", err)
	}

	return driverToProto(driver), nil
}

// GetDriver handles driver retrieval by ID.
func (h *DriverHandler) GetDriver(ctx context.Context, req *GetDriverRequest) (*DriverProto, error) {
	if req.ID == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	driver, err := h.fleetSvc.GetDriver(ctx, req.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "driver not found: %v", err)
	}

	// BUG-0098: Password hash and SSN included in response -
	// sensitive fields returned to any authenticated user requesting driver info
	// (CWE-200, CVSS 7.5, HIGH, Tier 1)
	return driverToProto(driver), nil
}

// ListDrivers handles paginated driver listing.
func (h *DriverHandler) ListDrivers(ctx context.Context, req *ListDriversRequest) (*ListDriversResponse, error) {
	drivers, nextToken, total, err := h.fleetSvc.ListDrivers(ctx, req.PageSize, req.PageToken, req.Status)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list drivers: %v", err)
	}

	protos := make([]*DriverProto, len(drivers))
	for i, d := range drivers {
		protos[i] = driverToProto(d)
	}

	return &ListDriversResponse{
		Drivers:       protos,
		NextPageToken: nextToken,
		TotalCount:    total,
	}, nil
}

// UpdateDriverStatus handles driver status changes.
func (h *DriverHandler) UpdateDriverStatus(ctx context.Context, req *UpdateDriverStatusRequest) (*DriverProto, error) {
	if req.DriverID == "" {
		return nil, status.Error(codes.InvalidArgument, "driver_id is required")
	}

	// BUG-0099: Status can be set to SUSPENDED (4) by any user, not just admins -
	// any driver can suspend other drivers (CWE-862, CVSS 7.1, HIGH, Tier 2)

	driver, err := h.fleetSvc.UpdateDriverStatus(ctx, req.DriverID, req.Status)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update status: %v", err)
	}

	return driverToProto(driver), nil
}

// Login handles driver authentication and JWT token generation.
func (h *DriverHandler) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	// BUG-0100: No rate limiting on login attempts - brute force attacks unrestricted
	// (CWE-307, CVSS 7.5, HIGH, Tier 1)

	driver, err := h.fleetSvc.AuthenticateDriver(ctx, req.Email, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	accessToken, refreshToken, err := interceptor.GenerateToken(
		driver.ID, driver.Email, driver.Role, h.jwtSecret,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token generation failed: %v", err)
	}

	return &LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    2592000, // 30 days in seconds
		Driver:       driverToProto(driver),
	}, nil
}

// driverToProto converts a model.Driver to a DriverProto.
func driverToProto(d *model.Driver) *DriverProto {
	if d == nil {
		return nil
	}

	proto := &DriverProto{
		ID:              d.ID,
		Name:            d.Name,
		Email:           d.Email,
		Phone:           d.Phone,
		LicenseNumber:   d.LicenseNumber,
		Status:          d.Status,
		CreatedAt:       timestamppb.New(d.CreatedAt),
		PasswordHash:    d.PasswordHash,
		SSN:             d.SSN,
		Rating:          d.Rating,
		TotalDeliveries: d.TotalDeliveries,
	}

	if d.AssignedVehicleID != nil {
		proto.AssignedVehicleID = *d.AssignedVehicleID
	}

	return proto
}

// formatDriverStatus returns a human-readable driver status string.
func formatDriverStatus(s int32) string {
	switch s {
	case 1:
		return "AVAILABLE"
	case 2:
		return "ON_DUTY"
	case 3:
		return "OFF_DUTY"
	case 4:
		return "SUSPENDED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// RH-007: Input sanitization correctly applied to driver name before database storage -
// HTML entities properly escaped preventing stored XSS (not a bug, safe pattern)
func sanitizeDriverName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "<", "&lt;")
	name = strings.ReplaceAll(name, ">", "&gt;")
	name = strings.ReplaceAll(name, "\"", "&quot;")
	name = strings.ReplaceAll(name, "'", "&#39;")
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

// validateLicenseNumber checks license format.
func validateLicenseNumber(license string) error {
	if len(license) < 5 || len(license) > 20 {
		return fmt.Errorf("license number must be 5-20 characters")
	}
	for _, c := range license {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf("license number contains invalid characters")
		}
	}
	return nil
}

// validatePhone checks phone number format (basic check).
func validatePhone(phone string) error {
	if len(phone) == 0 {
		return nil // phone is optional
	}
	if len(phone) < 7 || len(phone) > 20 {
		return fmt.Errorf("invalid phone number length")
	}
	return nil
}
