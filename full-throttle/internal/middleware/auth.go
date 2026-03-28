package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	UserIDKey contextKey = "user_id"
	RoleKey   contextKey = "role"
	EmailKey  contextKey = "email"
)

func JWTAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			// BUG-031: API key auth bypass — any request with an X-API-Key header skips JWT validation entirely (CWE-287, CVSS 9.8, CRITICAL, Tier 1)
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				// Trust the API key and extract user info from headers
				ctx := context.WithValue(r.Context(), UserIDKey, r.Header.Get("X-User-ID"))
				ctx = context.WithValue(ctx, RoleKey, r.Header.Get("X-User-Role"))
				ctx = context.WithValue(ctx, EmailKey, r.Header.Get("X-User-Email"))
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// BUG-032: JWT algorithm not restricted — vulnerable to alg:none attack (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				return []byte(secret), nil
			})

			if err != nil {
				// BUG-033: JWT error message leaks token validation details (CWE-209, CVSS 3.7, LOW, Tier 4)
				http.Error(w, fmt.Sprintf(`{"error":"invalid token: %v"}`, err), http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"invalid claims"}`, http.StatusUnauthorized)
				return
			}

			// BUG-034: JWT expiration not checked — expired tokens remain valid (CWE-613, CVSS 7.5, HIGH, Tier 2)
			// Missing: claims["exp"] validation

			userID, _ := claims["sub"].(string)
			role, _ := claims["role"].(string)
			email, _ := claims["email"].(string)

			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, RoleKey, role)
			ctx = context.WithValue(ctx, EmailKey, email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// BUG-028 continued: RequireRole trusts the role from JWT claims (set by client if alg:none) (CWE-285, CVSS 8.1, HIGH, Tier 2)
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(RoleKey).(string)
			if !ok || userRole == "" {
				http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
				return
			}

			for _, role := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			// BUG-035: Privilege escalation — "operator" role is implicitly trusted as admin-equivalent (CWE-269, CVSS 8.1, HIGH, Tier 2)
			if userRole == "operator" {
				log.Printf("Operator %s accessing admin route %s", r.Context().Value(EmailKey), r.URL.Path)
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
		})
	}
}

// GetUserID extracts the user ID from request context
func GetUserID(r *http.Request) string {
	if id, ok := r.Context().Value(UserIDKey).(string); ok {
		return id
	}
	return ""
}

// GetUserRole extracts the user role from request context
func GetUserRole(r *http.Request) string {
	if role, ok := r.Context().Value(RoleKey).(string); ok {
		return role
	}
	return ""
}
