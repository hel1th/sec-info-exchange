package httptransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hel1th/sec-info-exchange/internal/usecase"
)

func securityOptions() ServerOptions {
	return ServerOptions{
		ReaderKey: strings.Repeat("r", 32), WriterKey: strings.Repeat("w", 32),
		RequestsPerMinute: 120, MaxBodyBytes: 256, Ready: func(context.Context) error { return nil },
	}
}

func TestAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, key, method string
		status            int
	}{
		{"missing", "", http.MethodGet, http.StatusUnauthorized},
		{"unknown", "invalid", http.MethodGet, http.StatusUnauthorized},
		{"reader read", strings.Repeat("r", 32), http.MethodGet, http.StatusOK},
		{"reader write", strings.Repeat("r", 32), http.MethodPost, http.StatusForbidden},
		{"writer write", strings.Repeat("w", 32), http.MethodPost, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepository{}
			h := NewServerHandler(usecase.NewThreatService(repo), securityOptions())
			path := "/info/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			if tc.method == http.MethodPost {
				path = "/info"
			}
			r := httptest.NewRequestWithContext(t.Context(), tc.method, path,
				strings.NewReader(`{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"test","severity":"low"}`))
			r.Header.Set("X-API-Key", tc.key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d, want %d", w.Code, tc.status)
			}
			if w.Header().Get("X-Request-ID") == "" {
				t.Fatal("missing request ID")
			}
			if tc.status >= 400 && repo.calls != 0 {
				t.Fatal("unauthorized request reached repository")
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	for _, knownLength := range []bool{true, false} {
		opts := securityOptions()
		repo := &fakeRepository{}
		h := NewServerHandler(usecase.NewThreatService(repo), opts)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/info",
			strings.NewReader(`{"name":"`+strings.Repeat("a", 300)+`"}`))
		if !knownLength {
			r.ContentLength = -1
		}
		r.Header.Set("X-API-Key", opts.WriterKey)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge || repo.calls != 0 {
			t.Fatalf("got %d, calls=%d", w.Code, repo.calls)
		}
	}
}

func TestRateLimitAndReadiness(t *testing.T) {
	opts := securityOptions()
	opts.RequestsPerMinute = 1
	opts.Ready = func(context.Context) error { return errors.New("database secret") }
	h := NewServerHandler(usecase.NewThreatService(&fakeRepository{}), opts)
	for i := range 2 {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/info/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
		r.Header.Set("X-API-Key", opts.ReaderKey)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i == 1 && (w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "") {
			t.Fatalf("rate limit: %d", w.Code)
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		want := http.StatusOK
		if path == "/readyz" {
			want = http.StatusServiceUnavailable
		}
		if w.Code != want || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("probe: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestLimiterBoundedAndConcurrent(t *testing.T) {
	l := newWindowLimiter(5, 1)
	now := time.Now()
	l.now = func() time.Time { return now }
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if l.allow("one") {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 5 || l.allow("two") {
		t.Fatal("limit or capacity exceeded")
	}
	now = now.Add(time.Minute)
	if !l.allow("two") || len(l.entries) != 1 {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestRateLimitScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		requests []struct {
			addr, key, forwarded string
			want                 int
		}
	}{
		{"IP isolation and untrusted forwarding", []struct {
			addr, key, forwarded string
			want                 int
		}{
			{"192.0.2.1:1000", "", "", http.StatusUnauthorized},
			{"192.0.2.1:2000", "", "", http.StatusUnauthorized},
			{"192.0.2.1:3000", "", "192.0.2.99", http.StatusTooManyRequests},
			{"192.0.2.2:1000", "", "", http.StatusUnauthorized},
		}},
		{"key shared across IPs and roles independent", []struct {
			addr, key, forwarded string
			want                 int
		}{
			{"192.0.2.1:1000", strings.Repeat("r", 32), "", http.StatusOK},
			{"192.0.2.2:1000", strings.Repeat("r", 32), "", http.StatusTooManyRequests},
			{"192.0.2.2:2000", strings.Repeat("w", 32), "", http.StatusOK},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := securityOptions()
			opts.RequestsPerMinute = 1
			h := NewServerHandler(usecase.NewThreatService(&fakeRepository{}), opts)
			for i, step := range tc.requests {
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/info/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
				r.RemoteAddr = step.addr
				r.Header.Set("X-API-Key", step.key)
				r.Header.Set("X-Forwarded-For", step.forwarded)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != step.want {
					t.Fatalf("request %d: got %d, want %d", i, w.Code, step.want)
				}
			}
		})
	}
}
