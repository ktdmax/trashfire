package handler

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bonecorp/bone-song-rpc/internal/interceptor"
	"github.com/bonecorp/bone-song-rpc/internal/model"
	"github.com/bonecorp/bone-song-rpc/internal/service"
)

// RouteHandler implements gRPC route management endpoints.
type RouteHandler struct {
	fleetSvc *service.FleetService
}

// NewRouteHandler creates a new RouteHandler.
func NewRouteHandler(fleetSvc *service.FleetService) *RouteHandler {
	return &RouteHandler{fleetSvc: fleetSvc}
}

// RouteProto is a simplified protobuf-like struct for route responses.
type RouteProto struct {
	ID                       string                 `json:"id"`
	VehicleID                string                 `json:"vehicle_id"`
	DriverID                 string                 `json:"driver_id"`
	Waypoints                []*WaypointProto       `json:"waypoints"`
	Status                   int32                  `json:"status"`
	TotalDistanceKm          float64                `json:"total_distance_km"`
	EstimatedDurationMinutes int32                  `json:"estimated_duration_minutes"`
	ScheduledStart           *timestamppb.Timestamp `json:"scheduled_start"`
	ActualStart              *timestamppb.Timestamp `json:"actual_start"`
	CompletedAt              *timestamppb.Timestamp `json:"completed_at"`
	Notes                    string                 `json:"notes"`
	Priority                 int32                  `json:"priority"`
}

// WaypointProto is a simplified protobuf-like struct for waypoint data.
type WaypointProto struct {
	Latitude   float64                `json:"latitude"`
	Longitude  float64                `json:"longitude"`
	Address    string                 `json:"address"`
	Sequence   int32                  `json:"sequence"`
	ETA        *timestamppb.Timestamp `json:"eta"`
	ArrivedAt  *timestamppb.Timestamp `json:"arrived_at"`
	DeliveryID string                 `json:"delivery_id"`
}

// CreateRouteRequest mirrors proto definition.
type CreateRouteRequest struct {
	VehicleID      string           `json:"vehicle_id"`
	DriverID       string           `json:"driver_id"`
	Waypoints      []*WaypointProto `json:"waypoints"`
	Priority       int32            `json:"priority"`
	ScheduledStart *time.Time       `json:"scheduled_start"`
}

// AssignRouteRequest mirrors proto definition.
type AssignRouteRequest struct {
	RouteID   string `json:"route_id"`
	VehicleID string `json:"vehicle_id"`
	DriverID  string `json:"driver_id"`
}

// GetRouteRequest mirrors proto definition.
type GetRouteRequest struct {
	ID string `json:"id"`
}

// ListRoutesRequest mirrors proto definition.
type ListRoutesRequest struct {
	PageSize  int32  `json:"page_size"`
	PageToken string `json:"page_token"`
	DriverID  string `json:"driver_id"`
	VehicleID string `json:"vehicle_id"`
	Status    int32  `json:"status"`
}

// ListRoutesResponse mirrors proto definition.
type ListRoutesResponse struct {
	Routes        []*RouteProto `json:"routes"`
	NextPageToken string        `json:"next_page_token"`
	TotalCount    int32         `json:"total_count"`
}

// CompleteRouteRequest mirrors proto definition.
type CompleteRouteRequest struct {
	RouteID         string `json:"route_id"`
	CompletionNotes string `json:"completion_notes"`
}

// CreateRoute handles route creation.
func (h *RouteHandler) CreateRoute(ctx context.Context, req *CreateRouteRequest) (*RouteProto, error) {
	// BUG-0089: No validation that vehicle_id and driver_id exist before route creation -
	// can create orphaned routes with non-existent references (CWE-20, CVSS 4.3, MEDIUM, Tier 2)

	if req.VehicleID == "" || req.DriverID == "" {
		return nil, status.Error(codes.InvalidArgument, "vehicle_id and driver_id are required")
	}

	route, err := h.fleetSvc.CreateRoute(ctx, req.VehicleID, req.DriverID, req.Priority, req.ScheduledStart)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create route: %v", err)
	}

	// Add waypoints if provided
	if len(req.Waypoints) > 0 {
		// BUG-0090: No limit on number of waypoints per route - can create routes with
		// millions of waypoints, exhausting database storage (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
		waypoints := make([]*model.Waypoint, len(req.Waypoints))
		for i, wp := range req.Waypoints {
			waypoints[i] = &model.Waypoint{
				Latitude:   wp.Latitude,
				Longitude:  wp.Longitude,
				Address:    wp.Address,
				Sequence:   wp.Sequence,
				DeliveryID: wp.DeliveryID,
			}
		}
		if err := h.fleetSvc.AddWaypoints(ctx, route.ID, waypoints); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to add waypoints: %v", err)
		}
	}

	// Reload with waypoints
	route, _ = h.fleetSvc.GetRoute(ctx, route.ID)
	return routeToProto(route), nil
}

// AssignRoute handles route assignment to vehicle and driver.
func (h *RouteHandler) AssignRoute(ctx context.Context, req *AssignRouteRequest) (*RouteProto, error) {
	if err := interceptor.CheckRole(ctx, "admin", "dispatcher"); err != nil {
		return nil, err
	}

	if req.RouteID == "" {
		return nil, status.Error(codes.InvalidArgument, "route_id is required")
	}

	route, err := h.fleetSvc.AssignRoute(ctx, req.RouteID, req.VehicleID, req.DriverID)
	if err != nil {
		// BUG-0091: Internal error details leaked to client including database state -
		// reveals vehicle/driver status information (CWE-209, CVSS 3.7, LOW, Tier 2)
		return nil, status.Errorf(codes.Internal, "failed to assign route: %v", err)
	}

	return routeToProto(route), nil
}

// GetRoute handles route retrieval.
func (h *RouteHandler) GetRoute(ctx context.Context, req *GetRouteRequest) (*RouteProto, error) {
	if req.ID == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	// BUG-0092: No authorization check - any authenticated user can view any route,
	// including routes from other fleet organizations (CWE-862, CVSS 5.3, MEDIUM, Tier 1)
	route, err := h.fleetSvc.GetRoute(ctx, req.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "route not found: %v", err)
	}

	return routeToProto(route), nil
}

// ListRoutes handles paginated route listing.
func (h *RouteHandler) ListRoutes(ctx context.Context, req *ListRoutesRequest) (*ListRoutesResponse, error) {
	routes, nextToken, total, err := h.fleetSvc.ListRoutes(ctx, req.PageSize, req.PageToken, req.DriverID, req.VehicleID, req.Status)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list routes: %v", err)
	}

	protos := make([]*RouteProto, len(routes))
	for i, r := range routes {
		protos[i] = routeToProto(r)
	}

	return &ListRoutesResponse{
		Routes:        protos,
		NextPageToken: nextToken,
		TotalCount:    total,
	}, nil
}

// CompleteRoute handles route completion.
func (h *RouteHandler) CompleteRoute(ctx context.Context, req *CompleteRouteRequest) (*RouteProto, error) {
	if req.RouteID == "" {
		return nil, status.Error(codes.InvalidArgument, "route_id is required")
	}

	// BUG-0093: No check that the requesting driver is the one assigned to the route -
	// any driver can mark any route as completed (CWE-862, CVSS 6.5, MEDIUM, Tier 2)

	// BUG-0094: No check that route is currently active before completing -
	// can complete already-completed or cancelled routes, corrupting statistics
	// (CWE-754, CVSS 4.3, MEDIUM, Tier 2)

	route, err := h.fleetSvc.CompleteRoute(ctx, req.RouteID, req.CompletionNotes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to complete route: %v", err)
	}

	return routeToProto(route), nil
}

// routeToProto converts a model.Route to a RouteProto.
func routeToProto(r *model.Route) *RouteProto {
	if r == nil {
		return nil
	}

	proto := &RouteProto{
		ID:                       r.ID,
		VehicleID:                r.VehicleID,
		DriverID:                 r.DriverID,
		Status:                   r.Status,
		TotalDistanceKm:          r.TotalDistanceKm,
		EstimatedDurationMinutes: r.EstimatedDurationMinutes,
		Notes:                    r.Notes,
		Priority:                 r.Priority,
	}

	if r.ScheduledStart != nil {
		proto.ScheduledStart = timestamppb.New(*r.ScheduledStart)
	}
	if r.ActualStart != nil {
		proto.ActualStart = timestamppb.New(*r.ActualStart)
	}
	if r.CompletedAt != nil {
		proto.CompletedAt = timestamppb.New(*r.CompletedAt)
	}

	if r.Waypoints != nil {
		proto.Waypoints = make([]*WaypointProto, len(r.Waypoints))
		for i, wp := range r.Waypoints {
			proto.Waypoints[i] = waypointToProto(wp)
		}
	}

	return proto
}

// waypointToProto converts a model.Waypoint to a WaypointProto.
func waypointToProto(wp *model.Waypoint) *WaypointProto {
	if wp == nil {
		return nil
	}

	proto := &WaypointProto{
		Latitude:   wp.Latitude,
		Longitude:  wp.Longitude,
		Address:    wp.Address,
		Sequence:   wp.Sequence,
		DeliveryID: wp.DeliveryID,
	}

	if wp.ETA != nil {
		proto.ETA = timestamppb.New(*wp.ETA)
	}
	if wp.ArrivedAt != nil {
		proto.ArrivedAt = timestamppb.New(*wp.ArrivedAt)
	}

	return proto
}

// formatRouteStatus returns a human-readable route status string.
func formatRouteStatus(s int32) string {
	switch s {
	case 1:
		return "PLANNED"
	case 2:
		return "ACTIVE"
	case 3:
		return "COMPLETED"
	case 4:
		return "CANCELLED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}
