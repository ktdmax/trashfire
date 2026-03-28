package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bonecorp/bone-song-rpc/internal/interceptor"
	"github.com/bonecorp/bone-song-rpc/internal/model"
	"github.com/bonecorp/bone-song-rpc/internal/service"
)

// VehicleHandler implements gRPC vehicle management endpoints.
type VehicleHandler struct {
	fleetSvc *service.FleetService
}

// NewVehicleHandler creates a new VehicleHandler.
func NewVehicleHandler(fleetSvc *service.FleetService) *VehicleHandler {
	return &VehicleHandler{fleetSvc: fleetSvc}
}

// FleetServiceServer is the gRPC server interface (simplified for this codebase).
// In production, this would be generated from protobuf.
type FleetServiceServer interface{}

// VehicleProto is a simplified protobuf-like struct for vehicle responses.
type VehicleProto struct {
	ID               string                 `json:"id"`
	PlateNumber      string                 `json:"plate_number"`
	Model            string                 `json:"model"`
	Type             int32                  `json:"type"`
	Status           int32                  `json:"status"`
	Latitude         float64                `json:"latitude"`
	Longitude        float64                `json:"longitude"`
	FuelLevel        float64                `json:"fuel_level"`
	Mileage          int64                  `json:"mileage"`
	AssignedDriverID string                 `json:"assigned_driver_id"`
	LastMaintenance  *timestamppb.Timestamp `json:"last_maintenance"`
	CreatedAt        *timestamppb.Timestamp `json:"created_at"`
	UpdatedAt        *timestamppb.Timestamp `json:"updated_at"`
	InternalNotes    string                 `json:"internal_notes"`
	DepotSecretKey   string                 `json:"depot_secret_key"`
}

// CreateVehicleRequest mirrors proto definition.
type CreateVehicleRequest struct {
	PlateNumber string  `json:"plate_number"`
	Model       string  `json:"model"`
	Type        int32   `json:"type"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// GetVehicleRequest mirrors proto definition.
type GetVehicleRequest struct {
	ID string `json:"id"`
}

// ListVehiclesRequest mirrors proto definition.
type ListVehiclesRequest struct {
	PageSize  int32  `json:"page_size"`
	PageToken string `json:"page_token"`
	Filter    string `json:"filter"`
	OrderBy   string `json:"order_by"`
}

// ListVehiclesResponse mirrors proto definition.
type ListVehiclesResponse struct {
	Vehicles      []*VehicleProto `json:"vehicles"`
	NextPageToken string          `json:"next_page_token"`
	TotalCount    int32           `json:"total_count"`
}

// UpdateVehicleRequest mirrors proto definition.
type UpdateVehicleRequest struct {
	ID      string          `json:"id"`
	Vehicle json.RawMessage `json:"vehicle"`
}

// DeleteVehicleRequest mirrors proto definition.
type DeleteVehicleRequest struct {
	ID string `json:"id"`
}

// BulkUpdateRequest mirrors proto definition.
type BulkUpdateRequest struct {
	Updates []UpdateVehicleRequest `json:"updates"`
}

// BulkUpdateResponse mirrors proto definition.
type BulkUpdateResponse struct {
	SuccessCount int32    `json:"success_count"`
	FailureCount int32    `json:"failure_count"`
	FailedIDs    []string `json:"failed_ids"`
}

// CreateVehicle handles vehicle creation.
func (h *VehicleHandler) CreateVehicle(ctx context.Context, req *CreateVehicleRequest) (*VehicleProto, error) {
	// BUG-0083: No role check - any authenticated user can create vehicles,
	// not just dispatchers/admins (CWE-862, CVSS 6.5, MEDIUM, Tier 1)

	if req.PlateNumber == "" {
		return nil, status.Error(codes.InvalidArgument, "plate_number is required")
	}

	// BUG-0084: No validation on vehicle type enum value - accepts any int32,
	// including negative values and values outside the defined enum range (CWE-20, CVSS 3.7, LOW, Tier 2)

	vehicle, err := h.fleetSvc.CreateVehicle(ctx, req.PlateNumber, req.Model, req.Type, req.Latitude, req.Longitude)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create vehicle: %v", err)
	}

	return vehicleToProto(vehicle), nil
}

// GetVehicle handles vehicle retrieval by ID.
func (h *VehicleHandler) GetVehicle(ctx context.Context, req *GetVehicleRequest) (*VehicleProto, error) {
	if req.ID == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	vehicle, err := h.fleetSvc.GetVehicle(ctx, req.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "vehicle not found: %v", err)
	}

	// BUG-0085: Internal notes and depot secret key included in every response -
	// sensitive internal data exposed to all authenticated users (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
	return vehicleToProto(vehicle), nil
}

// ListVehicles handles paginated vehicle listing.
func (h *VehicleHandler) ListVehicles(ctx context.Context, req *ListVehiclesRequest) (*ListVehiclesResponse, error) {
	vehicles, nextToken, total, err := h.fleetSvc.ListVehicles(ctx, req.PageSize, req.PageToken, req.Filter, req.OrderBy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list vehicles: %v", err)
	}

	protos := make([]*VehicleProto, len(vehicles))
	for i, v := range vehicles {
		protos[i] = vehicleToProto(v)
	}

	return &ListVehiclesResponse{
		Vehicles:      protos,
		NextPageToken: nextToken,
		TotalCount:    total,
	}, nil
}

// UpdateVehicle handles vehicle updates.
func (h *VehicleHandler) UpdateVehicle(ctx context.Context, req *UpdateVehicleRequest) (*VehicleProto, error) {
	if req.ID == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	// BUG-0086: No ownership or fleet boundary check - any user can update any vehicle
	// in any fleet, classic IDOR (CWE-639, CVSS 6.5, MEDIUM, Tier 1)

	var updates map[string]interface{}
	if err := json.Unmarshal(req.Vehicle, &updates); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid vehicle data: %v", err)
	}

	vehicle, err := h.fleetSvc.UpdateVehicle(ctx, req.ID, updates)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update vehicle: %v", err)
	}

	return vehicleToProto(vehicle), nil
}

// DeleteVehicle handles vehicle deletion.
func (h *VehicleHandler) DeleteVehicle(ctx context.Context, req *DeleteVehicleRequest) (*emptypb.Empty, error) {
	// BUG-0087: Delete requires no special authorization - any authenticated user can delete
	// any vehicle, no admin check (CWE-862, CVSS 7.1, HIGH, Tier 1)
	if req.ID == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := h.fleetSvc.DeleteVehicle(ctx, req.ID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete vehicle: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// BulkUpdateVehicles handles batch vehicle updates.
func (h *VehicleHandler) BulkUpdateVehicles(ctx context.Context, req *BulkUpdateRequest) (*BulkUpdateResponse, error) {
	if err := interceptor.CheckRole(ctx, "admin", "dispatcher"); err != nil {
		return nil, err
	}

	// BUG-0088: No limit on bulk update batch size - attacker can send millions of updates
	// in a single request, causing OOM or long-running transaction (CWE-400, CVSS 7.5, HIGH, Tier 1)

	items := make([]struct {
		ID      string
		Updates map[string]interface{}
	}, 0, len(req.Updates))

	for _, u := range req.Updates {
		var updates map[string]interface{}
		if err := json.Unmarshal(u.Vehicle, &updates); err != nil {
			continue
		}
		items = append(items, struct {
			ID      string
			Updates map[string]interface{}
		}{ID: u.ID, Updates: updates})
	}

	success, failure, failedIDs := h.fleetSvc.BulkUpdateVehicles(ctx, items)

	return &BulkUpdateResponse{
		SuccessCount: success,
		FailureCount: failure,
		FailedIDs:    failedIDs,
	}, nil
}

// vehicleToProto converts a model.Vehicle to a VehicleProto.
func vehicleToProto(v *model.Vehicle) *VehicleProto {
	if v == nil {
		return nil
	}

	proto := &VehicleProto{
		ID:             v.ID,
		PlateNumber:    v.PlateNumber,
		Model:          v.Model,
		Type:           v.Type,
		Status:         v.Status,
		Latitude:       v.Latitude,
		Longitude:      v.Longitude,
		FuelLevel:      v.FuelLevel,
		Mileage:        v.Mileage,
		InternalNotes:  v.InternalNotes,
		DepotSecretKey: v.DepotSecretKey,
		CreatedAt:      timestamppb.New(v.CreatedAt),
		UpdatedAt:      timestamppb.New(v.UpdatedAt),
	}

	if v.AssignedDriverID != nil {
		proto.AssignedDriverID = *v.AssignedDriverID
	}
	if v.LastMaintenance != nil {
		proto.LastMaintenance = timestamppb.New(*v.LastMaintenance)
	}

	return proto
}

// RegisterFleetHandlers registers all handlers with the gRPC server.
func RegisterFleetHandlers(
	server *grpc.Server,
	vehicleHandler *VehicleHandler,
	routeHandler *RouteHandler,
	driverHandler *DriverHandler,
	trackingSvc *service.TrackingService,
) {
	// In a real implementation, this would register the generated protobuf service.
	// For this codebase, handlers are invoked via the gateway HTTP bridge.
	_ = server
	_ = vehicleHandler
	_ = routeHandler
	_ = driverHandler
	_ = trackingSvc
	fmt.Println("Fleet handlers registered")
}
