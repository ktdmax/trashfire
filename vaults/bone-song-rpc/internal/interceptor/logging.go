package interceptor

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor returns a unary server interceptor that logs requests.
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Extract peer info
		peerInfo, _ := peer.FromContext(ctx)
		clientIP := "unknown"
		if peerInfo != nil {
			clientIP = peerInfo.Addr.String()
		}

		// Extract metadata
		md, _ := metadata.FromIncomingContext(ctx)

		// BUG-0052: Full request body logged including passwords, tokens, and PII -
		// sensitive data written to log files (CWE-532, CVSS 5.5, MEDIUM, Tier 1)
		reqJSON, _ := json.Marshal(req)

		logrus.WithFields(logrus.Fields{
			"method":     info.FullMethod,
			"client_ip":  clientIP,
			"request":    string(reqJSON),
			"metadata":   md,
			"start_time": start.Format(time.RFC3339),
		}).Info("gRPC request started")

		// BUG-0053: Panic recovery catches all panics and returns generic error -
		// masks critical errors and prevents crash dumps for debugging.
		// Also continues serving after potentially corrupted state (CWE-755, CVSS 5.9, MEDIUM, Tier 3)
		defer func() {
			if r := recover(); r != nil {
				logrus.WithFields(logrus.Fields{
					"method":     info.FullMethod,
					"panic":      fmt.Sprintf("%v", r),
					"stack":      string(debug.Stack()),
					"client_ip":  clientIP,
				}).Error("Panic recovered in gRPC handler")
			}
		}()

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		// BUG-0054: Full response body logged including sensitive data returned to client -
		// database records with PII/secrets written to logs (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
		respJSON, _ := json.Marshal(resp)

		logrus.WithFields(logrus.Fields{
			"method":    info.FullMethod,
			"duration":  duration.String(),
			"code":      code.String(),
			"client_ip": clientIP,
			"response":  string(respJSON),
			"error":     fmt.Sprintf("%v", err),
		}).Info("gRPC request completed")

		return resp, err
	}
}

// StreamLoggingInterceptor returns a stream server interceptor that logs stream lifecycle.
func StreamLoggingInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()

		peerInfo, _ := peer.FromContext(ss.Context())
		clientIP := "unknown"
		if peerInfo != nil {
			clientIP = peerInfo.Addr.String()
		}

		logrus.WithFields(logrus.Fields{
			"method":        info.FullMethod,
			"client_ip":     clientIP,
			"is_client_stream": info.IsClientStream,
			"is_server_stream": info.IsServerStream,
		}).Info("gRPC stream started")

		// BUG-0055: Stream wrapper logs every message in both directions -
		// high-frequency location updates flood logs and expose all tracking data
		// (CWE-779, CVSS 3.7, LOW, Tier 3)
		wrappedStream := &loggingServerStream{
			ServerStream: ss,
			method:       info.FullMethod,
			clientIP:     clientIP,
		}

		err := handler(srv, wrappedStream)

		duration := time.Since(start)
		logrus.WithFields(logrus.Fields{
			"method":        info.FullMethod,
			"duration":      duration.String(),
			"client_ip":     clientIP,
			"messages_sent": wrappedStream.sentCount,
			"messages_recv": wrappedStream.recvCount,
			"error":         fmt.Sprintf("%v", err),
		}).Info("gRPC stream completed")

		return err
	}
}

type loggingServerStream struct {
	grpc.ServerStream
	method    string
	clientIP  string
	sentCount int64
	recvCount int64
}

func (s *loggingServerStream) SendMsg(m interface{}) error {
	s.sentCount++
	msgJSON, _ := json.Marshal(m)
	logrus.WithFields(logrus.Fields{
		"method":   s.method,
		"direction": "send",
		"count":    s.sentCount,
		"message":  string(msgJSON),
	}).Trace("Stream message")
	return s.ServerStream.SendMsg(m)
}

func (s *loggingServerStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		s.recvCount++
		msgJSON, _ := json.Marshal(m)
		logrus.WithFields(logrus.Fields{
			"method":   s.method,
			"direction": "recv",
			"count":    s.recvCount,
			"message":  string(msgJSON),
		}).Trace("Stream message")
	}
	return err
}

// RH-004: Duration measurement uses monotonic clock (time.Since) which is immune to
// wall clock adjustments - this is the correct approach (not a bug, safe pattern)
