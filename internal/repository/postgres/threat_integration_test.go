package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hel1th/sec-info-exchange/internal/domain"
	"github.com/hel1th/sec-info-exchange/internal/repository/postgres"
	"github.com/hel1th/sec-info-exchange/internal/usecase"
	"github.com/hel1th/sec-info-exchange/migrations"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "test_" + strings.ToLower(rand.Text())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, createErr := admin.Exec(ctx, "CREATE SCHEMA "+identifier); createErr != nil {
		t.Fatal(createErr)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, dropErr := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); dropErr != nil {
			t.Error(dropErr)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	for range 2 {
		if err := migrations.Up(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func TestRepositoryIntegration(t *testing.T) {
	pool := testPool(t)
	repo := postgres.New(pool)
	ctx := t.Context()
	id := strings.Repeat("a", 32)
	now := time.Now().UTC().Truncate(time.Microsecond)
	entity, err := domain.NewThreat(id, domain.ThreatData{
		Name: "Trojan", Severity: domain.SeverityHigh, Description: "original", Tags: []string{"malware"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, getErr := repo.Get(ctx, id); !errors.Is(getErr, usecase.ErrNotFound) {
		t.Fatalf("missing get: %v", getErr)
	}
	if _, updateErr := repo.Update(ctx, id, entity.ThreatData, now); !errors.Is(updateErr, usecase.ErrNotFound) {
		t.Fatalf("missing update: %v", updateErr)
	}
	checkConcurrentCreate(t, repo, entity)
	data := domain.ThreatData{Name: "Updated", Severity: domain.SeverityLow, Tags: []string{}}
	updated, err := repo.Update(ctx, id, data, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.CreatedAt.Equal(now) || !updated.UpdatedAt.Equal(now.Add(time.Second)) || updated.Description != "" {
		t.Fatalf("incorrect update: %+v", updated)
	}
	if len(updated.Tags) != 0 {
		t.Fatal("tags were not cleared")
	}
	fetched, err := postgres.New(pool).Get(ctx, id)
	if err != nil || fetched.Name != "Updated" {
		t.Fatalf("read persisted data: %+v, %v", fetched, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := repo.Get(canceled, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func checkConcurrentCreate(t *testing.T, repo *postgres.Repository, entity domain.Threat) {
	t.Helper()
	ctx := t.Context()
	const writers = 16
	results := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() { _, createErr := repo.Create(ctx, entity); results <- createErr })
	}
	wg.Wait()
	close(results)
	created, conflicts := 0, 0
	for createErr := range results {
		switch {
		case createErr == nil:
			created++
		case errors.Is(createErr, usecase.ErrConflict):
			conflicts++
		default:
			t.Fatal(createErr)
		}
	}
	if created != 1 || conflicts != writers-1 {
		t.Fatalf("created=%d conflicts=%d", created, conflicts)
	}
}
