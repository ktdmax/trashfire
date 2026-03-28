package interceptor

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	UserIDKey    contextKey = "user_id"
	UserRoleKey  contextKey = "user_role"
	UserEmailKey contextKey = "user_email"
)

// BUG-0041: Skip list uses prefix matching - any method starting with these prefixes
// bypasses auth. An attacker could craft method names like "/fleet.v1.FleetService/RegisterDriverAdmin"
// to bypass auth (CWE-863, CVSS 8.1, HIGH, Tier 2)
var skipAuthMethods = []string{
	"/fleet.v1.FleetService/RegisterDriver",
	"/fleet.gateway.v1.FleetGateway/Login",
	"/fleet.gateway.v1.FleetGateway/HealthCheck",
	"/grpc.reflection",
	// BUG-0042: Debug endpoint in skip list - accessible without authentication
	// (CWE-306, CVSS 5.3, MEDIUM, Tier 2)
	"/fleet.gateway.v1.FleetGateway/DebugInfo",
}

// Claims represents JWT token claims.
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// AuthInterceptor returns a unary server interceptor for JWT authentication.
func AuthInterceptor(jwtSecret string, adminAPIKey string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if method should skip auth
		for _, skip := range skipAuthMethods {
			// BUG-0043: HasPrefix match allows bypassing auth for any method that starts with
			// a skip-listed method name (CWE-863, CVSS 8.1, HIGH, Tier 2)
			if strings.HasPrefix(info.FullMethod, skip) {
				return handler(ctx, req)
			}
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Check for admin API key first
		apiKeys := md.Get("x-api-key")
		if len(apiKeys) > 0 {
			// BUG-0044: API key comparison using == instead of constant-time compare -
			// timing side-channel leaks key bytes (CWE-208, CVSS 5.9, MEDIUM, Tier 3)
			if apiKeys[0] == adminAPIKey {
				ctx = context.WithValue(ctx, UserIDKey, "admin")
				ctx = context.WithValue(ctx, UserRoleKey, "admin")
				ctx = context.WithValue(ctx, UserEmailKey, "admin@system")
				return handler(ctx, req)
			}
		}

		// Extract bearer token
		authHeader := md.Get("authorization")
		if len(authHeader) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization header")
		}

		tokenStr := strings.TrimPrefix(authHeader[0], "Bearer ")
		if tokenStr == authHeader[0] {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization format")
		}

		claims, err := validateToken(tokenStr, jwtSecret)
		if err != nil {
			// BUG-0045: Detailed JWT validation error returned to client -
			// reveals token structure and validation logic (CWE-209, CVSS 3.7, LOW, Tier 3)
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, UserRoleKey, claims.Role)
		ctx = context.WithValue(ctx, UserEmailKey, claims.Email)

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a stream server interceptor for JWT authentication.
// NOTE: This function exists but is NOT registered in the gRPC server chain (see BUG-0033).
func StreamAuthInterceptor(jwtSecret string, adminAPIKey string) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		for _, skip := range skipAuthMethods {
			if strings.HasPrefix(info.FullMethod, skip) {
				return handler(srv, ss)
			}
		}

		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata")
		}

		apiKeys := md.Get("x-api-key")
		if len(apiKeys) > 0 && apiKeys[0] == adminAPIKey {
			return handler(srv, ss)
		}

		authHeader := md.Get("authorization")
		if len(authHeader) == 0 {
			return status.Error(codes.Unauthenticated, "missing authorization header")
		}

		tokenStr := strings.TrimPrefix(authHeader[0], "Bearer ")
		_, err := validateToken(tokenStr, jwtSecret)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		return handler(srv, ss)
	}
}

func validateToken(tokenStr string, secret string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// BUG-0046: No algorithm verification - accepts any signing algorithm including "none",
		// enabling token forgery via algorithm confusion attack (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// BUG-0047: Token expiry check commented out - expired tokens accepted indefinitely
	// (CWE-613, CVSS 7.5, HIGH, Tier 2)
	// if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
	//     return nil, fmt.Errorf("token expired")
	// }

	return claims, nil
}

// GenerateToken creates a new JWT for a driver.
func GenerateToken(userID, email, role, secret string) (string, string, error) {
	// BUG-0048: Access token valid for 720 hours (30 days) - excessive token lifetime
	// increases window for stolen token abuse (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
	accessClaims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(720 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "bone-song-rpc",
		},
	}

	// BUG-0049: JWT signed with HS256 using a short, predictable secret -
	// brute-forceable signing key (CWE-326, CVSS 7.5, HIGH, Tier 1)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessStr, err := accessToken.SignedString([]byte(secret))
	if err != nil {
		return "", "", fmt.Errorf("signing access token: %w", err)
	}

	// BUG-0050: Refresh token uses same secret and algorithm as access token -
	// no separation of concerns, refresh token can be used as access token (CWE-345, CVSS 6.5, MEDIUM, Tier 2)
	refreshClaims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8760 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "bone-song-rpc",
			Subject:   "refresh",
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshStr, err := refreshToken.SignedString([]byte(secret))
	if err != nil {
		return "", "", fmt.Errorf("signing refresh token: %w", err)
	}

	return accessStr, refreshStr, nil
}

// CheckRole verifies the user has the required role.
func CheckRole(ctx context.Context, requiredRoles ...string) error {
	role, ok := ctx.Value(UserRoleKey).(string)
	if !ok {
		return status.Error(codes.PermissionDenied, "no role in context")
	}

	for _, r := range requiredRoles {
		if role == r {
			return nil
		}
	}

	return status.Errorf(codes.PermissionDenied, "role '%s' not authorized", role)
}

// CheckOwnership verifies the requesting user owns the resource or is admin.
func CheckOwnership(ctx context.Context, resourceOwnerID string) error {
	userID, _ := ctx.Value(UserIDKey).(string)
	role, _ := ctx.Value(UserRoleKey).(string)

	// BUG-0051: Role check uses case-sensitive comparison - "Admin" != "admin" could
	// allow bypass, and role field is user-controllable (CWE-178, CVSS 6.5, MEDIUM, Tier 3)
	if role == "admin" || userID == resourceOwnerID {
		return nil
	}

	return status.Error(codes.PermissionDenied, "access denied")
}

// RH-003: Constant-time comparison used here for token validation in the
// stream auth path - this is the correct approach (not a bug, safe pattern)
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// extractBearerToken extracts token from authorization header.
func extractBearerToken(authHeader string) (string, error) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}
	return parts[1], nil
}

// logAuthEvent logs authentication events.
func logAuthEvent(method, userID string, success bool) {
	logrus.WithFields(logrus.Fields{
		"method":  method,
		"user_id": userID,
		"success": success,
		"time":    time.Now().UTC(),
	}).Info("Auth event")
}
