package transport

import (
	"net/http"
	"time"

	"github.com/kompotkot/tripidium/internal/service"
	"github.com/kompotkot/tripidium/internal/transport/runtime"
)

type authContextKey string

// responseWriter wraps http.ResponseWriter to capture status code and bytes written
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// loggerMiddleware logs every request: method, path, status, duration
func (s *Server) loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)
		args := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"duration_ms", duration.Milliseconds(),
			"remote_addr", r.RemoteAddr,
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			args = append(args, "x_forwarded_for", xff)
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			args = append(args, "x_real_ip", xrip)
		}
		s.deps.Log.Info("http_request", args...)
	})
}

// Handle panic errors to prevent server shutdown
func (s *Server) panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				s.deps.Log.Info("http_panic", "error", err)
				http.Error(w, "Internal server error", 500)
			}
		}()
		// There will be a defer with panic handler in each next function
		next.ServeHTTP(w, r)
	})
}

// CORS middleware
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var allowedOrigin string
		if s.deps.Cfg.CORSWhitelist["*"] {
			allowedOrigin = "*"
		} else {
			origin := r.Header.Get("Origin")
			if _, ok := s.deps.Cfg.CORSWhitelist[origin]; ok {
				allowedOrigin = origin
			}
		}

		if allowedOrigin != "" {
			allowHeaders := "Content-Type"
			if allowedOrigin != "*" {
				allowHeaders += ", Authorization"
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				// Don't allow credentials for wildcard
			}
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", s.deps.Cfg.CORSAllowedDefaultMethods)
			// Credentials are cookies, authorization headers, or TLS client certificates
			w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates an access token and stores auth identity in request context
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		identity, err := service.ParseAndVerifyAccessTokenFromAuthHeader(authorization, s.deps.Cfg.AuthConfig)
		if err != nil {
			s.deps.Log.Info("auth_unauthorized", "path", r.URL.Path, "error", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := runtime.WithAuthIdentity(r.Context(), identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
