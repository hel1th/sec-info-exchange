package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hel1th/sec-info-exchange/internal/domain"
	"github.com/hel1th/sec-info-exchange/internal/usecase"
)

type fakeRepository struct {
	stored domain.Threat
	err    error
	calls  int
}

func (f *fakeRepository) Create(_ context.Context, entity domain.Threat) (domain.Threat, error) {
	f.calls++
	f.stored = entity
	return entity, f.err
}

func (f *fakeRepository) Get(_ context.Context, _ string) (domain.Threat, error) {
	f.calls++
	return f.stored, f.err
}

func (f *fakeRepository) Update(_ context.Context, md5 string, data domain.ThreatData, now time.Time) (domain.Threat, error) {
	f.calls++
	f.stored.MD5, f.stored.ThreatData, f.stored.UpdatedAt = md5, data, now
	return f.stored, f.err
}

func TestHTTPCreateAndReplace(t *testing.T) {
	repo := &fakeRepository{}
	api := NewHandler(usecase.NewThreatService(repo))
	post := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/info", strings.NewReader(
		`{"md5":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","name":" Trojan ","severity":"high","description":"old","tags":[" malware "]}`))
	w := httptest.NewRecorder()
	api.ServeHTTP(w, post)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if repo.stored.MD5 != strings.Repeat("a", 32) || repo.stored.Name != "Trojan" || repo.stored.Tags[0] != "malware" {
		t.Fatalf("mapping or normalization failed: %+v", repo.stored)
	}
	created := repo.stored.CreatedAt
	put := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/info/"+repo.stored.MD5,
		strings.NewReader(`{"name":"Updated","severity":"low"}`))
	w = httptest.NewRecorder()
	api.ServeHTTP(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if repo.stored.Description != "" || len(repo.stored.Tags) != 0 || !repo.stored.CreatedAt.Equal(created) {
		t.Fatal("PUT must clear omitted attributes and preserve creation time")
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if tags, ok := response["tags"].([]any); !ok || len(tags) != 0 {
		t.Fatal("empty tags must be a JSON array")
	}
}

func TestHTTPRejectsInvalidRequestsBeforeRepository(t *testing.T) {
	repo := &fakeRepository{}
	api := NewHandler(usecase.NewThreatService(repo))
	for _, body := range []string{
		`{`, `null`, `{}`, `{} {}`, `{"md5":"bad","name":"x","severity":"low"}`,
		`{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"x"}`,
		`{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"x","severity":"wrong"}`,
		`{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"x","severity":"low","tags":["x"," x "]}`,
	} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/info", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: got %d", body, w.Code)
		}
	}
	if repo.calls != 0 {
		t.Fatal("invalid input reached persistence")
	}
}

func TestHTTPMapsErrorsAndHidesInternals(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{fmt.Errorf("wrapped: %w", usecase.ErrNotFound), http.StatusNotFound},
		{fmt.Errorf("wrapped: %w", usecase.ErrConflict), http.StatusConflict},
		{errors.New("secret database connection string"), http.StatusInternalServerError},
	} {
		repo := &fakeRepository{err: tc.err}
		w := httptest.NewRecorder()
		NewHandler(usecase.NewThreatService(repo)).ServeHTTP(w,
			httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/info", strings.NewReader(
				`{"md5":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"x","severity":"low"}`)))
		if w.Code != tc.status {
			t.Fatalf("want %d, got %d", tc.status, w.Code)
		}
		if strings.Contains(w.Body.String(), "secret") {
			t.Fatal("internal error leaked")
		}
	}
}
