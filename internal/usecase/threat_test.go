package usecase

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hel1th/sec-info-exchange/internal/domain"
)

type repositoryStub struct {
	create func(context.Context, domain.Threat) (domain.Threat, error)
	get    func(context.Context, string) (domain.Threat, error)
	update func(context.Context, string, domain.ThreatData, time.Time) (domain.Threat, error)
}

func (r repositoryStub) Create(ctx context.Context, entity domain.Threat) (domain.Threat, error) {
	return r.create(ctx, entity)
}

func (r repositoryStub) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	return r.get(ctx, md5)
}

func (r repositoryStub) Update(ctx context.Context, md5 string, data domain.ThreatData, now time.Time) (domain.Threat, error) {
	return r.update(ctx, md5, data, now)
}

func TestCreateNormalizesAndPassesContext(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	input := CreateThreatInput{
		MD5:  strings.Repeat("A", 32),
		Data: ThreatData{Name: " Trojan ", Severity: string(domain.SeverityHigh), Tags: []string{" malware "}},
	}
	calls := 0
	s := NewThreatService(repositoryStub{create: func(gotCtx context.Context, entity domain.Threat) (domain.Threat, error) {
		calls++
		if gotCtx != ctx {
			t.Fatal("context was replaced")
		}
		if entity.MD5 != strings.Repeat("a", 32) || entity.Name != "Trojan" || entity.Tags[0] != "malware" {
			t.Fatalf("not normalized: %+v", entity)
		}
		if !entity.CreatedAt.Equal(now) || !entity.UpdatedAt.Equal(now) {
			t.Fatal("incorrect timestamps")
		}
		return entity, nil
	}})
	s.now = func() time.Time { return now }
	got, err := s.Create(ctx, input)
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d, error=%v", calls, err)
	}
	input.Data.Tags[0] = "changed"
	if got.Tags[0] != "malware" {
		t.Fatal("entity aliases input tags")
	}
}

func TestGetNormalizesIdentifier(t *testing.T) {
	ctx := t.Context()
	want := domain.Threat{MD5: strings.Repeat("a", 32)}
	s := NewThreatService(repositoryStub{get: func(gotCtx context.Context, id string) (domain.Threat, error) {
		if gotCtx != ctx || id != want.MD5 {
			t.Fatal("incorrect repository arguments")
		}
		return want, nil
	}})
	got, err := s.Get(ctx, GetThreatInput{MD5: strings.Repeat("A", 32)})
	if err != nil || !reflect.DeepEqual(ThreatOutput(got), toThreatOutput(want)) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestUpdateReplacesWithoutReading(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	want := domain.Threat{MD5: strings.Repeat("a", 32), CreatedAt: now.Add(-time.Hour), UpdatedAt: now}
	calls := 0
	s := NewThreatService(repositoryStub{update: func(gotCtx context.Context, id string, data domain.ThreatData, updated time.Time) (domain.Threat, error) {
		calls++
		if gotCtx != ctx || id != want.MD5 || !updated.Equal(now) {
			t.Fatal("incorrect repository arguments")
		}
		if data.Name != "Updated" || data.Description != "" || len(data.Tags) != 0 {
			t.Fatal("incorrect replacement data")
		}
		return want, nil
	}})
	s.now = func() time.Time { return now }
	got, err := s.Update(ctx, UpdateThreatInput{MD5: strings.Repeat("A", 32), Data: ThreatData{Name: " Updated ", Severity: string(domain.SeverityLow)}})
	if err != nil || calls != 1 || !reflect.DeepEqual(ThreatOutput(got), toThreatOutput(want)) {
		t.Fatalf("got %+v, calls=%d, error=%v", got, calls, err)
	}
}

func TestInvalidInputDoesNotReachRepository(t *testing.T) {
	// Any repository invocation panics because no callbacks are configured.
	s := NewThreatService(repositoryStub{})
	id := strings.Repeat("a", 32)
	valid := ThreatData{Name: "Threat", Severity: string(domain.SeverityLow)}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"create id", func() error { _, err := s.Create(t.Context(), CreateThreatInput{MD5: "bad", Data: valid}); return err }},
		{"create data", func() error { _, err := s.Create(t.Context(), CreateThreatInput{MD5: id}); return err }},
		{"get id", func() error { _, err := s.Get(t.Context(), GetThreatInput{MD5: "bad"}); return err }},
		{"update id", func() error { _, err := s.Update(t.Context(), UpdateThreatInput{MD5: "bad", Data: valid}); return err }},
		{"update data", func() error { _, err := s.Update(t.Context(), UpdateThreatInput{MD5: id}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, domain.ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestRepositoryErrorsRemainDiscoverable(t *testing.T) {
	id := strings.Repeat("a", 32)
	data := ThreatData{Name: "Threat", Severity: string(domain.SeverityLow)}
	for _, cause := range []error{ErrConflict, ErrNotFound, context.Canceled, context.DeadlineExceeded, errors.New("database unavailable")} {
		s := NewThreatService(repositoryStub{
			create: func(context.Context, domain.Threat) (domain.Threat, error) { return domain.Threat{}, cause },
			get:    func(context.Context, string) (domain.Threat, error) { return domain.Threat{}, cause },
			update: func(context.Context, string, domain.ThreatData, time.Time) (domain.Threat, error) {
				return domain.Threat{}, cause
			},
		})
		_, createErr := s.Create(t.Context(), CreateThreatInput{MD5: id, Data: data})
		_, getErr := s.Get(t.Context(), GetThreatInput{MD5: id})
		_, updateErr := s.Update(t.Context(), UpdateThreatInput{MD5: id, Data: data})
		for _, err := range []error{createErr, getErr, updateErr} {
			if !errors.Is(err, cause) {
				t.Fatalf("lost error identity: %v", err)
			}
		}
	}
}
