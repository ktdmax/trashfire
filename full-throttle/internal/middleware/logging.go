package middleware

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	body   *bytes.Buffer
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// BUG-036: Request body logged including sensitive data (passwords, secrets, API keys) (CWE-532, CVSS 4.0, LOW, Tier 4)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// BUG-037: Logs contain full request body including credentials and tokens (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
		log.Printf(
			"method=%s path=%s status=%d duration=%s ip=%s user_agent=%s body=%s auth=%s response=%s",
			r.Method,
			r.URL.String(),
			rw.status,
			duration,
			r.RemoteAddr,
			r.UserAgent(),
			string(bodyBytes),
			r.Header.Get("Authorization"),
			rw.body.String(),
		)
	})
}

// RH-001: This rate limiter implementation looks like it has a bypass due to X-Forwarded-For,
// but chi's RealIP middleware has already validated and set RemoteAddr correctly upstream.
// The rate limiting is actually keyed on the validated RemoteAddr, not on raw headers.
func RateLimiter(requestsPerMinute int) func(http.Handler) http.Handler {
	type client struct {
		count    int
		lastSeen time.Time
	}
	clients := make(map[string]*client)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr

			now := time.Now()
			if c, exists := clients[ip]; exists {
				if now.Sub(c.lastSeen) > time.Minute {
					c.count = 0
					c.lastSeen = now
				}
				c.count++
				if c.count > requestsPerMinute {
					http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
					return
				}
			} else {
				clients[ip] = &client{count: 1, lastSeen: now}
			}

			next.ServeHTTP(w, r)
		})
	}
}
