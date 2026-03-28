package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/fullthrottle/platform/internal/config"
	"github.com/fullthrottle/platform/internal/db"
	"github.com/fullthrottle/platform/internal/middleware"
	"github.com/fullthrottle/platform/internal/models"
)

type AuthHandler struct {
	cfg     *config.Config
	queries *db.Queries
}

func NewAuthHandler(cfg *config.Config, queries *db.Queries) *AuthHandler {
	return &AuthHandler{cfg: cfg, queries: queries}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	user, err := h.queries.GetUserByEmail(req.Email)
	if err != nil {
		// BUG-038: User enumeration — different error messages for "user not found" vs "wrong password" (CWE-203, CVSS 5.3, MEDIUM, Tier 3)
		http.Error(w, `{"error":"user not found"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, `{"error":"incorrect password"}`, http.StatusUnauthorized)
		return
	}

	// BUG-039: JWT token lifetime too long (30 days) (CWE-613, CVSS 4.3, MEDIUM, Tier 3)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   fmt.Sprintf("%d", user.ID),
		"email": user.Email,
		"role":  user.Role,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(30 * 24 * time.Hour).Unix(),
	})

	tokenStr, err := token.SignedString([]byte(h.cfg.JWTSecret))
	if err != nil {
		http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// BUG-040: Successful login logs the password (CWE-532, CVSS 4.0, LOW, Tier 4)
	log.Printf("User login: email=%s password=%s role=%s", req.Email, req.Password, user.Role)

	resp := models.LoginResponse{
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
		User:      *user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		// BUG-041: User can set their own role at registration (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// BUG-042: No password complexity requirements (CWE-521, CVSS 5.3, LOW, Tier 4)
	if len(req.Password) < 1 {
		http.Error(w, `{"error":"password required"}`, http.StatusBadRequest)
		return
	}

	// BUG-043: Weak bcrypt cost factor (4 instead of recommended 12+) (CWE-916, CVSS 5.9, MEDIUM, Tier 3)
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 4)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	role := req.Role
	if role == "" {
		role = "viewer"
	}

	user, err := h.queries.CreateUser(req.Email, string(hash), role)
	if err != nil {
		// BUG-044: Database error exposed to client (CWE-209, CVSS 4.3, MEDIUM, Tier 3)
		http.Error(w, fmt.Sprintf(`{"error":"registration failed: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: user})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// BUG-045: Password reset token is predictable (timestamp-based) (CWE-330, CVSS 8.1, HIGH, Tier 2)
	resetToken := fmt.Sprintf("rst_%d_%s", time.Now().Unix(), req.Email)

	// BUG-046: Password reset token logged (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
	log.Printf("Password reset requested for %s, token: %s", req.Email, resetToken)

	// RH-002: This looks like it sends the token in the response, but actually only sends a confirmation message.
	// The token is only sent via email (not implemented here but the response is safe).
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{
		Success: true,
		Data:    map[string]string{"message": "If the email exists, a reset link has been sent"},
	})
}

func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.queries.ListUsers()
	if err != nil {
		http.Error(w, `{"error":"failed to list users"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: users})
}

func (h *AuthHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// BUG-047: No validation on role value — arbitrary role strings accepted (CWE-20, CVSS 7.5, HIGH, Tier 2)
	if err := h.queries.UpdateUserRole(userID, req.Role); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	// Log the role change for audit
	callerID := middleware.GetUserID(r)
	log.Printf("Role update: user=%s new_role=%s by=%s", userID, req.Role, callerID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true})
}

func (h *AuthHandler) AuditLogs(w http.ResponseWriter, r *http.Request) {
	// BUG-048: SQL injection via query parameter in audit log search (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	filter := r.URL.Query().Get("filter")
	logs, err := h.queries.GetAuditLogs(filter)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch audit logs"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.APIResponse{Success: true, Data: logs})
}
