package service

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/bonecorp/bone-song-rpc/internal/model"
)

// TrackingService handles real-time vehicle tracking.
type TrackingService struct {
	db          *gorm.DB
	subscribers map[string][]chan *LocationUpdate
	mu          sync.RWMutex
	// BUG-0073: No limit on number of subscribers per vehicle -
	// unbounded channel creation leads to memory exhaustion (CWE-770, CVSS 6.5, MEDIUM, Tier 2)
}

// LocationUpdate represents a real-time location update for broadcasting.
type LocationUpdate struct {
	VehicleID string
	Latitude  float64
	Longitude float64
	SpeedKmh  float64
	Heading   float64
	Timestamp time.Time
}

// TrackingUpdate represents an event notification.
type TrackingUpdateMsg struct {
	VehicleID string
	EventType string
	Message   string
	Timestamp time.Time
}

// NewTrackingService creates a new TrackingService.
func NewTrackingService(db *gorm.DB) *TrackingService {
	ts := &TrackingService{
		db:          db,
		subscribers: make(map[string][]chan *LocationUpdate),
	}

	// Background stale subscriber cleanup
	// BUG-0074: Goroutine leak - cleanup routine has no shutdown mechanism,
	// runs forever even after service is done (CWE-401, CVSS 3.7, LOW, Tier 3)
	go ts.cleanupStaleSubscribers()

	return ts
}

// Subscribe registers a channel to receive location updates for a vehicle.
func (ts *TrackingService) Subscribe(vehicleID string) chan *LocationUpdate {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// BUG-0075: Unbuffered channel for subscriber - slow consumer blocks all publishers
	// for this vehicle, causing cascading delays (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
	ch := make(chan *LocationUpdate)
	ts.subscribers[vehicleID] = append(ts.subscribers[vehicleID], ch)

	logrus.WithFields(logrus.Fields{
		"vehicle_id":      vehicleID,
		"subscriber_count": len(ts.subscribers[vehicleID]),
	}).Debug("New subscriber added")

	return ch
}

// Unsubscribe removes a channel from the subscriber list.
func (ts *TrackingService) Unsubscribe(vehicleID string, ch chan *LocationUpdate) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	subs := ts.subscribers[vehicleID]
	for i, sub := range subs {
		if sub == ch {
			ts.subscribers[vehicleID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			break
		}
	}
}

// Publish sends a location update to all subscribers of a vehicle.
func (ts *TrackingService) Publish(update *LocationUpdate) {
	ts.mu.RLock()
	subs := ts.subscribers[update.VehicleID]
	ts.mu.RUnlock()

	for _, ch := range subs {
		// BUG-0076: Non-blocking send silently drops messages when channel is full -
		// location updates lost without any notification or logging (CWE-390, CVSS 3.7, LOW, Tier 3)
		select {
		case ch <- update:
		default:
			// message dropped
		}
	}
}

// StreamVehicleLocations streams location updates for specified vehicles.
func (ts *TrackingService) StreamVehicleLocations(vehicleIDs []string, intervalSeconds int32, sendFn func(*LocationUpdate) error) error {
	// BUG-0077: No maximum stream duration - client can hold stream open forever,
	// consuming server resources indefinitely (CWE-400, CVSS 6.5, MEDIUM, Tier 2)

	if intervalSeconds <= 0 {
		intervalSeconds = 5
	}

	// BUG-0078: No minimum interval check - client can request sub-second intervals,
	// causing excessive database queries and CPU usage (CWE-400, CVSS 5.3, MEDIUM, Tier 2)

	channels := make([]chan *LocationUpdate, 0, len(vehicleIDs))
	for _, vid := range vehicleIDs {
		ch := ts.Subscribe(vid)
		channels = append(channels, ch)
	}

	defer func() {
		for i, vid := range vehicleIDs {
			ts.Unsubscribe(vid, channels[i])
		}
	}()

	// Also poll database for latest positions
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, vid := range vehicleIDs {
				var vehicle model.Vehicle
				if err := ts.db.Select("id, latitude, longitude").
					Where("id = ?", vid).First(&vehicle).Error; err != nil {
					continue
				}

				update := &LocationUpdate{
					VehicleID: vehicle.ID,
					Latitude:  vehicle.Latitude,
					Longitude: vehicle.Longitude,
					Timestamp: time.Now(),
				}

				if err := sendFn(update); err != nil {
					return fmt.Errorf("sending location: %w", err)
				}
			}
		}
	}
}

// LiveTracking handles bidirectional streaming for real-time tracking.
func (ts *TrackingService) LiveTracking(
	ctx context.Context,
	recvFn func() (*LocationUpdate, error),
	sendFn func(*TrackingUpdateMsg) error,
) error {
	// BUG-0079: No rate limiting on incoming location updates - a compromised client
	// can flood the server with updates causing DoS (CWE-799, CVSS 6.5, MEDIUM, Tier 2)

	var wg sync.WaitGroup

	// Receive loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			update, err := recvFn()
			if err != nil {
				if err == io.EOF {
					return
				}
				logrus.WithError(err).Error("Error receiving tracking update")
				return
			}

			// BUG-0080: No validation on incoming coordinates - accepts NaN, Infinity,
			// or coordinates outside valid lat/lng range (CWE-20, CVSS 4.3, MEDIUM, Tier 2)

			// Store in database
			event := &model.TrackingEvent{
				VehicleID: update.VehicleID,
				Latitude:  update.Latitude,
				Longitude: update.Longitude,
				SpeedKmh:  update.SpeedKmh,
				Heading:   update.Heading,
				Timestamp: update.Timestamp,
			}
			ts.db.Create(event)

			// Update vehicle position
			ts.db.Model(&model.Vehicle{}).Where("id = ?", update.VehicleID).Updates(map[string]interface{}{
				"latitude":  update.Latitude,
				"longitude": update.Longitude,
			})

			// Broadcast to subscribers
			ts.Publish(update)

			// Check for geofence violations, speed alerts, etc.
			if update.SpeedKmh > 120 {
				alertMsg := &TrackingUpdateMsg{
					VehicleID: update.VehicleID,
					EventType: "SPEED_ALERT",
					Message:   fmt.Sprintf("Vehicle %s exceeding speed limit: %.1f km/h", update.VehicleID, update.SpeedKmh),
					Timestamp: time.Now(),
				}
				if err := sendFn(alertMsg); err != nil {
					logrus.WithError(err).Error("Error sending alert")
				}
			}
		}
	}()

	// Heartbeat loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				heartbeat := &TrackingUpdateMsg{
					EventType: "HEARTBEAT",
					Message:   "connection alive",
					Timestamp: time.Now(),
				}
				if err := sendFn(heartbeat); err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

// GetVehicleHistory retrieves location history for a vehicle.
func (ts *TrackingService) GetVehicleHistory(ctx context.Context, vehicleID string, start, end time.Time) ([]*model.TrackingEvent, error) {
	// BUG-0081: No limit on result set size - large time ranges return millions of rows,
	// causing OOM on the server (CWE-400, CVSS 6.5, MEDIUM, Tier 2)
	var events []*model.TrackingEvent
	if err := ts.db.WithContext(ctx).
		Where("vehicle_id = ? AND timestamp BETWEEN ? AND ?", vehicleID, start, end).
		Order("timestamp ASC").
		Find(&events).Error; err != nil {
		return nil, fmt.Errorf("fetching history: %w", err)
	}
	return events, nil
}

// cleanupStaleSubscribers periodically removes dead subscriber channels.
func (ts *TrackingService) cleanupStaleSubscribers() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		ts.mu.Lock()
		for vid, subs := range ts.subscribers {
			if len(subs) == 0 {
				delete(ts.subscribers, vid)
			}
		}
		ts.mu.Unlock()
	}
}

// ExportTrackingData exports all tracking events as chunks.
func (ts *TrackingService) ExportTrackingData(ctx context.Context, entityType string, sendChunkFn func([]byte, int32, bool) error) error {
	var events []*model.TrackingEvent

	// BUG-0082: Loads entire tracking_events table into memory at once -
	// multi-GB result set causes OOM crash (CWE-400, CVSS 7.5, HIGH, Tier 1)
	if err := ts.db.WithContext(ctx).Find(&events).Error; err != nil {
		return fmt.Errorf("exporting tracking data: %w", err)
	}

	chunkSize := 1000
	for i := 0; i < len(events); i += chunkSize {
		end := i + chunkSize
		if end > len(events) {
			end = len(events)
		}

		chunk := events[i:end]
		data := make([]byte, 0)
		for _, e := range chunk {
			line := fmt.Sprintf("%s,%s,%f,%f,%f,%f,%s\n",
				e.ID, e.VehicleID, e.Latitude, e.Longitude,
				e.SpeedKmh, e.Heading, e.Timestamp.Format(time.RFC3339))
			data = append(data, []byte(line)...)
		}

		isLast := end >= len(events)
		chunkNum := int32(i/chunkSize + 1)
		if err := sendChunkFn(data, chunkNum, isLast); err != nil {
			return fmt.Errorf("sending chunk: %w", err)
		}
	}

	return nil
}

// RH-006: Mutex properly used for subscriber map access with Lock/Unlock pairs -
// concurrent access to subscribers map is correctly synchronized (not a bug, safe pattern)
