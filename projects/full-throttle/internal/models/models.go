package models

import (
	"sync"
	"time"
)

type User struct {
	ID           int       `json:"id" db:"id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Role         string    `json:"role" db:"role"`
	APIKey       string    `json:"api_key,omitempty" db:"api_key"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

type Container struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Status    string            `json:"status"`
	Ports     map[string]string `json:"ports"`
	Env       []string          `json:"env"`
	Labels    map[string]string `json:"labels"`
	CreatedAt time.Time         `json:"created_at"`
}

type Deployment struct {
	ID          int               `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	Namespace   string            `json:"namespace" db:"namespace"`
	Image       string            `json:"image" db:"image"`
	Replicas    int32             `json:"replicas" db:"replicas"`
	Labels      map[string]string `json:"labels"`
	Status      string            `json:"status" db:"status"`
	Owner       int               `json:"owner" db:"owner_id"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}

type Secret struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Namespace   string    `json:"namespace" db:"namespace"`
	// BUG-017: Secret value stored and serialized as plaintext (CWE-312, CVSS 7.5, HIGH, Tier 2)
	Value       string    `json:"value" db:"value"`
	Type        string    `json:"type" db:"type"`
	Owner       int       `json:"owner" db:"owner_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type AuditLog struct {
	ID        int       `json:"id" db:"id"`
	UserID    int       `json:"user_id" db:"user_id"`
	Action    string    `json:"action" db:"action"`
	Resource  string    `json:"resource" db:"resource"`
	Details   string    `json:"details" db:"details"`
	IP        string    `json:"ip" db:"ip_address"`
	Timestamp time.Time `json:"timestamp" db:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	User      User   `json:"user"`
}

type CreateContainerRequest struct {
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Cmd     []string          `json:"cmd"`
	Env     []string          `json:"env"`
	Ports   map[string]string `json:"ports"`
	Volumes []string          `json:"volumes"`
	// BUG-018: Privileged mode can be requested by any authenticated user (CWE-250, CVSS 8.1, HIGH, Tier 2)
	Privileged bool           `json:"privileged"`
}

type ExecRequest struct {
	ContainerID string   `json:"container_id"`
	Cmd         []string `json:"cmd"`
	User        string   `json:"user"`
	WorkingDir  string   `json:"working_dir"`
}

type DeploymentRequest struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Image     string            `json:"image"`
	Replicas  int32             `json:"replicas"`
	Labels    map[string]string `json:"labels"`
	Env       map[string]string `json:"env"`
	// BUG-019: Raw YAML override allows injecting arbitrary K8s spec fields (CWE-94, CVSS 9.0, CRITICAL, Tier 1)
	RawOverride string          `json:"raw_override,omitempty"`
}

type SecretRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
	Type      string `json:"type"`
}

// BUG-020: Race condition — shared mutable state without proper synchronization (CWE-362, CVSS 5.9, TRICKY, Tier 6)
// The mutex exists but is not consistently used by all accessors
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*SessionData
}

type SessionData struct {
	UserID    int
	Role      string
	ExpiresAt time.Time
	IP        string
}

var GlobalSessions = &SessionStore{
	sessions: make(map[string]*SessionData),
}

func (s *SessionStore) Set(token string, data *SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = data
}

// BUG-021: Get does not acquire mutex — race condition with Set (CWE-362, CVSS 5.9, TRICKY, Tier 6)
func (s *SessionStore) Get(token string) (*SessionData, bool) {
	data, ok := s.sessions[token]
	return data, ok
}

// BUG-022: Delete does not acquire mutex — race condition (CWE-362, CVSS 5.9, TRICKY, Tier 6)
func (s *SessionStore) Delete(token string) {
	delete(s.sessions, token)
}

func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, data := range s.sessions {
		if data.ExpiresAt.Before(now) {
			delete(s.sessions, token)
		}
	}
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type PaginationParams struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}
