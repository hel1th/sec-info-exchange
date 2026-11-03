package httptransport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hel1th/sec-info-exchange/internal/api/generated"
)

// ServerOptions contains HTTP security and readiness dependencies.
type ServerOptions struct {
	ReaderKey         string
	WriterKey         string
	RequestsPerMinute int
	MaxBodyBytes      int64
	Ready             func(context.Context) error
}

// NewServerHandler adds authentication, authorization, limits and request logging.
// Health and readiness endpoints are intentionally public. Options must be validated by config.
func NewServerHandler(service ThreatService, opts ServerOptions) http.Handler {
	reader, writer := sha256.Sum256([]byte(opts.ReaderKey)), sha256.Sum256([]byte(opts.WriterKey))
	ipLimit := newWindowLimiter(opts.RequestsPerMinute*2, 4096)
	keyLimit := newWindowLimiter(opts.RequestsPerMinute, 2)
	api := NewHandler(service)
	secured := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !ipLimit.allow(ip) {
			rejectRate(w)
			return
		}
		key := sha256.Sum256([]byte(r.Header.Get("X-API-Key")))
		isReader := subtle.ConstantTimeCompare(key[:], reader[:]) == 1
		isWriter := subtle.ConstantTimeCompare(key[:], writer[:]) == 1
		if !isReader && !isWriter {
			writeJSON(w, http.StatusUnauthorized, generated.ErrorResponse{Message: "Invalid API key"})
			return
		}
		role := "reader"
		if isWriter {
			role = "writer"
		}
		if !keyLimit.allow(role) {
			rejectRate(w)
			return
		}
		if !isWriter && r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusForbidden, generated.ErrorResponse{Message: "Write access required"})
			return
		}
		if r.ContentLength > opts.MaxBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, generated.ErrorResponse{Message: "Request body too large"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, opts.MaxBodyBytes)
		api.ServeHTTP(w, r)
	})
	router := chi.NewRouter()
	router.Use(middleware.GetHead)
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, probeResponse{Status: "ok"})
	})
	router.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := opts.Ready(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, generated.ErrorResponse{Message: "Not ready"})
			return
		}
		writeJSON(w, http.StatusOK, probeResponse{Status: "ready"})
	})
	router.Mount("/", secured)
	return requestLog(router)
}

func rejectRate(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, generated.ErrorResponse{Message: "Rate limit exceeded"})
}

type probeResponse struct {
	Status string `json:"status"`
}

type window struct {
	start time.Time
	count int
}

type windowLimiter struct {
	mu       sync.Mutex
	entries  map[string]window
	limit    int
	capacity int
	now      func() time.Time
}

func newWindowLimiter(limit, capacity int) *windowLimiter {
	return &windowLimiter{entries: make(map[string]window), limit: limit, capacity: capacity, now: time.Now}
}

func (l *windowLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, exists := l.entries[key]
	if !exists && len(l.entries) >= l.capacity {
		for k, v := range l.entries {
			if now.Sub(v.start) >= time.Minute {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= l.capacity {
			return false
		}
	}
	if !exists || now.Sub(entry.start) >= time.Minute {
		entry = window{start: now}
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Unwrap supports http.ResponseController.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		start := time.Now()
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		slog.InfoContext(r.Context(), "request", "request_id", id, "method", r.Method,
			"status", strconv.Itoa(recorder.status), "duration", time.Since(start))
	})
}
